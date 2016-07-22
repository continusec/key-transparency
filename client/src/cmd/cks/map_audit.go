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

	"github.com/continusec/go-client/continusec"
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

type MutationWithJsonEntryResponse struct {
	MutationLogEntry []byte `json:"mutation_log_entry"`
	OHInput          []byte `json:"objecthash_input"`
}

type MutationEntry struct {
	LogEntry continusec.VerifiableEntry
	Value    continusec.VerifiableEntry
}

func (e *MutationEntry) LeafHash() ([]byte, error) {
	return e.LogEntry.LeafHash()
}

func (e *MutationEntry) Data() ([]byte, error) {
	return e.LogEntry.Data()
}

type MutationEntryFactory struct {
	ValueFactory continusec.VerifiableEntryFactory
}

func (f *MutationEntryFactory) CreateFromBytes(b []byte) (continusec.VerifiableEntry, error) {
	var mwjer MutationWithJsonEntryResponse
	err := json.NewDecoder(bytes.NewReader(b)).Decode(&mwjer)
	if err != nil {
		return nil, err
	}

	jsonEntry, err := continusec.JsonEntryFactory.CreateFromBytes(mwjer.MutationLogEntry)
	if err != nil {
		return nil, err
	}

	valEntry, err := f.ValueFactory.CreateFromBytes(mwjer.OHInput)
	if err != nil {
		return nil, err
	}

	return &MutationEntry{LogEntry: jsonEntry, Value: valEntry}, nil
}

func (f *MutationEntryFactory) Format() string {
	return "/xjson/mutation" // special hack
}

type AuditState struct {
	// Must be set
	Map *continusec.VerifiableMap

	// Must be set
	Context context.Context

	// Current mutation log tree head
	MutLogHead *continusec.LogTreeHead

	// Not set:
	Root            MapAuditNode // not a pointer so that we get good empty value
	MutLogHashStack [][]byte

	Size                 int64 // number of mutations processed, parallel arrays below
	MutationLogTreeHeads [][]byte
	MapTreeHeads         [][]byte
}

func (a *AuditState) ProcessUntilAtLeast(size int64) error {
	if size > a.Size {
		// For now, always just fetch until head.
		mutLog := a.Map.MutationLog()

		mutLogHead, err := mutLog.VerifiedLatestTreeHead(a.MutLogHead)
		if err != nil {
			return err
		}

		err = mutLog.VerifyEntries(a.Context, a.MutLogHead, mutLogHead, &MutationEntryFactory{ValueFactory: continusec.JsonEntryFactory}, func(idx int64, entry continusec.VerifiableEntry) error {
			mutationJson, err := entry.Data()
			if err != nil {
				return err
			}

			var mutation MapMutation
			err = json.Unmarshal(mutationJson, &mutation)
			if err != nil {
				return err
			}

			rh, err := AddMutationToTree(&a.Root, &mutation)
			if err != nil {
				return err
			}

			lh, err := entry.LeafHash()
			if err != nil {
				return err
			}

			a.MutLogHashStack = append(a.MutLogHashStack, lh)
			for z := idx; (z & 1) == 1; z >>= 1 {
				a.MutLogHashStack = append(a.MutLogHashStack[:len(a.MutLogHashStack)-2], continusec.NodeMerkleTreeHash(a.MutLogHashStack[len(a.MutLogHashStack)-2], a.MutLogHashStack[len(a.MutLogHashStack)-1]))
			}

			headHash := a.MutLogHashStack[len(a.MutLogHashStack)-1]
			for z := len(a.MutLogHashStack) - 2; z >= 0; z-- {
				headHash = continusec.NodeMerkleTreeHash(a.MutLogHashStack[z], headHash)
			}

			a.MutationLogTreeHeads = append(a.MutationLogTreeHeads, headHash)
			a.MapTreeHeads = append(a.MapTreeHeads, rh)

			return nil
		})
		if err != nil {
			return err
		}

		a.MutLogHead = mutLogHead
		a.Size = a.MutLogHead.TreeSize
	}

	if size > a.Size {
		return ErrBad
	}

	return nil
}

type mapHashResponse struct {
	MapHash []byte            `json:"map_hash"`
	LogSTH  *treeSizeResponse `json:"mutation_log"`
}

type treeSizeResponse struct {
	TreeSize int64  `json:"tree_size"`
	Hash     []byte `json:"tree_hash"`
}

func (a *AuditState) CheckTreeHeadEntry(idx int64, entry continusec.VerifiableEntry) error {
	treeHeadJson, err := entry.Data()
	if err != nil {
		return err
	}

	var mth mapHashResponse
	err = json.NewDecoder(bytes.NewReader(treeHeadJson)).Decode(&mth)
	if err != nil {
		return err
	}

	err = a.ProcessUntilAtLeast(mth.LogSTH.TreeSize)
	if err != nil {
		return err
	}

	// Check map root hash (subtract 1 from index since size 1 is the first meaningful)
	fmt.Println(mth.LogSTH.TreeSize - 1)
	if !bytes.Equal(a.MapTreeHeads[mth.LogSTH.TreeSize-1], mth.MapHash) {
		return ErrBad
	}

	// Check mutation log hash (subtract 1 from index since size 1 is the first meaningful)
	if !bytes.Equal(a.MutationLogTreeHeads[mth.LogSTH.TreeSize-1], mth.LogSTH.Hash) {
		return ErrBad
	}

	// All good
	return nil
}

func CreateInMemoryTreeHeadLogAuditFunction(ctx context.Context, vmap *continusec.VerifiableMap) continusec.AuditFunction {
	return (&AuditState{Map: vmap, Context: ctx}).CheckTreeHeadEntry
}

