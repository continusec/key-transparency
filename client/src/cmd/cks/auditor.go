package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"golang.org/x/net/context"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/urfave/cli"
)

var (
	ErrUnrecognizedMutation = errors.New("ErrUnrecognizedMutation")
	ErrBad                  = errors.New("ErrBad")
)

type MapMutation struct {
	Timestamp time.Time `json:"timestamp"`

	// One of "set", "delete", "update"
	Action string `json:"action"`
	Key    []byte `json:"key"`

	// Used for "set" and "update". This is the value that is used to calculated the leaf hash, so for JSON this is the objecthash.
	Value []byte `json:"value"`

	// Used for "update". This is the previous leaf hash (not value).
	PreviousLeafHash []byte `json:"previous"`
}

type MapTreeHead struct {
	MapHash     []byte `json:"map_hash"`
	MutationLog struct {
		TreeSize int64  `json:"tree_size"`
		Hash     []byte `json:"tree_hash"`
	} `json:"mutation_log"`
}

type MapAuditNode struct {
	// Calculated hash for this node, can be nil to indicate invalid
	Hash []byte

	// Our depth
	Depth int

	// Is this node a leaf? If so, left/right are ignored and RemPath/LeafHash must be set
	Leaf bool

	// Ignored if unless leaf is set. Remaining Path
	KeyPath []bool

	// Ignored if unless leaf is set. Actual value (differs from Hash since Hash takes into account RemPath)
	LeafHash []byte

	// The Left and Right child nodes. May be nil.
	Left, Right *MapAuditNode
}

func (node *MapAuditNode) Dump() {
	if node.Leaf {
		fmt.Printf("%*sLeaf (%d)\n", node.Depth*4, "", node.Depth)
	} else {
		fmt.Printf("%*sParent (%d)\n", node.Depth*4, "", node.Depth)
		fmt.Printf("%*sLeft\n", node.Depth*4, "")
		if node.Left == nil {
			fmt.Printf("%*sdefault\n", (node.Depth+1)*4, "")
		} else {
			node.Left.Dump()
		}
		fmt.Printf("%*sRight\n", node.Depth*4, "")
		if node.Right == nil {
			fmt.Printf("%*sdefault\n", (node.Depth+1)*4, "")
		} else {
			node.Right.Dump()
		}
	}
}

// Return hash, calculating if necessary
func (node *MapAuditNode) CalcHash() []byte {
	if node.Hash == nil {
		if node.Leaf {
			node.Hash = node.LeafHash
			for i := 256; i > node.Depth; i-- {
				if node.KeyPath[i-1] {
					node.Hash = continusec.NodeMerkleTreeHash(DefaultMapValues[i], node.Hash)
				} else {
					node.Hash = continusec.NodeMerkleTreeHash(node.Hash, DefaultMapValues[i])
				}
			}
		} else {
			var left, right []byte
			if node.Left == nil {
				left = DefaultMapValues[node.Depth+1]
			} else {
				left = node.Left.CalcHash()
			}
			if node.Right == nil {
				right = DefaultMapValues[node.Depth+1]
			} else {
				right = node.Right.CalcHash()
			}
			node.Hash = continusec.NodeMerkleTreeHash(left, right)
		}
	}
	return node.Hash
}

var (
	DefaultMapValues = continusec.GenerateMapDefaultLeafValues()
)

func AddMutationToTree(root *MapAuditNode, mut *MapMutation) ([]byte, error) {
	keyPath := continusec.ConstructMapKeyPath(mut.Key)
	head := root

	// First, set head to as far down as we can go
	for next := head; next != nil; {
		head.Hash = nil
		head = next
		if keyPath[head.Depth] {
			next = head.Right
		} else {
			next = head.Left
		}
	}

	// If we haven't found our leaf
	if !(head.Leaf && reflect.DeepEqual(keyPath, head.KeyPath)) {
		// Now, create as many single parents as needed until we diverge
		for next := head; next.Leaf && keyPath[next.Depth-1] == next.KeyPath[next.Depth-1]; {
			head = next
			child := &MapAuditNode{
				Depth:    head.Depth + 1,
				Leaf:     true,
				KeyPath:  head.KeyPath,
				LeafHash: head.LeafHash,
			}
			head.Leaf, head.LeafHash, head.KeyPath = false, nil, nil
			if child.KeyPath[head.Depth] {
				head.Left, head.Right = nil, child
			} else {
				head.Left, head.Right = child, nil
			}
			head.Hash = nil
			next = child
		}
		child := &MapAuditNode{
			Depth:    head.Depth + 1,
			Leaf:     true,
			KeyPath:  keyPath,
			LeafHash: DefaultMapValues[256],
		}
		if child.KeyPath[head.Depth] {
			head.Right = child
		} else {
			head.Left = child
		}
		head.Hash = nil
		head = child
	}

	switch mut.Action {
	case "set":
		head.LeafHash = continusec.LeafMerkleTreeHash(mut.Value)
	case "delete":
		head.LeafHash = DefaultMapValues[256]
	case "update":
		if bytes.Equal(head.LeafHash, mut.PreviousLeafHash) {
			head.LeafHash = continusec.LeafMerkleTreeHash(mut.Value)
		}
	default:
		return nil, ErrUnrecognizedMutation
	}
	head.Hash = nil

	return root.CalcHash(), nil
}

func auditMap(vmap *continusec.VerifiableMap) error {
	maxNum := continusec.Head

	mutLog := vmap.MutationLog()

	fmt.Println("Fetching mutation log head...")
	mutLogHead, err := mutLog.TreeHead(maxNum)
	if err != nil {
		return err
	}
	root := &MapAuditNode{}
	roots := make([][]byte, 0)
	roots = append(roots, root.CalcHash())
	fmt.Println("Received size:", mutLogHead.TreeSize)
	fmt.Println("Fetching all mutation log entries, verifying that together that match the mutation log head, and calculating map root hashes at each point...")

	err = mutLog.VerifyEntries(context.Background(), nil, mutLogHead, continusec.JsonEntryFactory, func(idx int64, entry continusec.VerifiableEntry) error {
		mutationJson, err := entry.Data()
		if err != nil {
			return err
		}

		var mutation MapMutation
		err = json.Unmarshal(mutationJson, &mutation)
		if err != nil {
			return err
		}

		rh, err := AddMutationToTree(root, &mutation)
		if err != nil {
			return err
		}

		fmt.Println("Map root hash:", idx+1, base64.StdEncoding.EncodeToString(rh))

		roots = append(roots, root.CalcHash())

		return nil
	})
	if err != nil {
		return err
	}

	// Now make sure that the logged tree heads match those calculated.
	thLog := vmap.TreeHeadLog()
	fmt.Println("Fetching tree head log head...")
	thLogHead, err := thLog.TreeHead(maxNum)
	fmt.Println("Received size:", thLogHead.TreeSize)
	if err != nil {
		return err
	}
	fmt.Println("Fetching all tree head items, and verifying that each really is from the previous list of calculated map heads, and that the head for the tree head log matches.")
	err = thLog.VerifyEntries(context.Background(), nil, thLogHead, continusec.JsonEntryFactory, func(idx int64, entry continusec.VerifiableEntry) error {
		treeHeadJson, err := entry.Data()
		if err != nil {
			return err
		}

		var mth MapTreeHead
		err = json.Unmarshal(treeHeadJson, &mth)
		if err != nil {
			return err
		}

		if mth.MutationLog.TreeSize < int64(len(roots)) {
			if bytes.Equal(roots[mth.MutationLog.TreeSize], mth.MapHash) {
				return nil
			} else {
				return ErrBad
			}
		} else {
			return ErrBad
		}
	})
	if err != nil {
		return err
	}

	fmt.Println("Done. Audit completed successfully.")

	return nil
}

func audit(db *bolt.DB, c *cli.Context) error {
	vmap, err := getMap()
	if err != nil {
		return err
	}

	err = auditMap(vmap)
	if err != nil {
		return err
	}

	fmt.Println("Success!")

	return nil
}
