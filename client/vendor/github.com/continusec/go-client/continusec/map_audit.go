/*
   Copyright 2016 Continusec Pty Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package continusec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"golang.org/x/net/context"
)

// mapMutation represents an entry in the Mutation Log for a map
type mapMutation struct {
	// When the mutation entry was generated
	Timestamp time.Time `json:"timestamp"`

	// One of "set", "delete", "update"
	Action string `json:"action"`

	// Which key did this affect
	Key []byte `json:"key"`

	// Used for "set" and "update". This is the value that is used to calculated the leaf hash, so for Json this is the objecthash.
	Value []byte `json:"value"`

	// Used for "update". This is the previous leaf hash (not value).
	PreviousLeafHash []byte `json:"previous"`
}

// MapAuditNode is an internal structure used for auditing maps
// It holds the current state of a map and is not go-routine safe.
type mapAuditNode struct {
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
	Left, Right *mapAuditNode
}

// Dump the map node and children to stdout
func (node *mapAuditNode) Dump() {
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

// Return hash for this node, calculating if necessary
func (node *mapAuditNode) CalcHash() []byte {
	if node.Hash == nil {
		if node.Leaf {
			node.Hash = node.LeafHash
			for i := 256; i > node.Depth; i-- {
				if node.KeyPath[i-1] {
					node.Hash = NodeMerkleTreeHash(defaultLeafValues[i], node.Hash)
				} else {
					node.Hash = NodeMerkleTreeHash(node.Hash, defaultLeafValues[i])
				}
			}
		} else {
			var left, right []byte
			if node.Left == nil {
				left = defaultLeafValues[node.Depth+1]
			} else {
				left = node.Left.CalcHash()
			}
			if node.Right == nil {
				right = defaultLeafValues[node.Depth+1]
			} else {
				right = node.Right.CalcHash()
			}
			node.Hash = NodeMerkleTreeHash(left, right)
		}
	}
	return node.Hash
}

// Given a root node, update it with a given map mutation, returning the new
// root hash.
func addMutationToTree(root *mapAuditNode, mut *mapMutation) ([]byte, error) {
	keyPath := ConstructMapKeyPath(mut.Key)
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
			child := &mapAuditNode{
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
		child := &mapAuditNode{
			Depth:    head.Depth + 1,
			Leaf:     true,
			KeyPath:  keyPath,
			LeafHash: defaultLeafValues[256],
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
		head.LeafHash = LeafMerkleTreeHash(mut.Value)
	case "delete":
		head.LeafHash = defaultLeafValues[256]
	case "update":
		if bytes.Equal(head.LeafHash, mut.PreviousLeafHash) {
			head.LeafHash = LeafMerkleTreeHash(mut.Value)
		}
	default:
		return nil, ErrVerificationFailed
	}
	head.Hash = nil

	return root.CalcHash(), nil
}

// MutationWithJsonEntryResponse is the structured used when requesting experimental
// type /xsjon/mutation as the entry type.
type mutationWithJsonEntryResponse struct {
	// MutationLogEntry contains the bytes for the mutation log JSON entry
	MutationLogEntry []byte `json:"mutation_log_entry"`

	// OHInput contains the bytes used for the input to make the object hash that is
	// the value in the MutationLogEntry
	OHInput []byte `json:"objecthash_input"`
}

// MutationEntry is a type of VerifiableEntry that contains both the
// log entry, and then separately the value used in that log entry. This is useful to use
// when the values in a MutationLog are stored as /xjson, and auditors need access to the
// actual value itself. While just the hash of the value is sufficient to audit that the
// map is operating correctly, auditors often need to audit properties of the underlying
// entry as well which is why it is made available.
type mutationEntry struct {
	LogEntry VerifiableEntry
	Value    VerifiableEntry
}

// LeafHash returns the leaf hash for the wrapped LogEntry
func (e *mutationEntry) LeafHash() ([]byte, error) {
	return e.LogEntry.LeafHash()
}

// Data returns the data for the wrapped LogEntry
func (e *mutationEntry) Data() ([]byte, error) {
	return e.LogEntry.Data()
}

// MutationEntryFactory will create instances of MutationEntry on-demand, using the
// ValueFactory as the factory for creating the actual values for the MutationEntry.
// This should be set to match the type of entry stored as the map values.
// MutationEntryFactory should only be used with Mutation Logs.
type mutationEntryFactory struct {
	ValueFactory VerifiableEntryFactory
}

// isSpecial determines whether special handling is needed for values.
// If the underlying value format is Json or RedactedJson, then we need to request
// the special mutation format, else we should just request xjson, since the value
// is included as raw bytes in the mutation entry.
func (f *mutationEntryFactory) isSpecial() bool {
	return strings.HasPrefix(f.ValueFactory.Format(), "/xjson")
}

// CreateFromBytes creates a new instance of MutationEntry. In addition, if a separate
// value is returned by the server (e.g. the underlying bytes for an objecthash map value)
// then this will verify that this value matches the objecthash map value.
func (f *mutationEntryFactory) CreateFromBytes(b []byte) (VerifiableEntry, error) {
	var mwjer mutationWithJsonEntryResponse
	var valEntry VerifiableEntry

	// First, find where the bytes are for that mutation entry
	bytesForMutation := b
	if f.isSpecial() {
		err := json.NewDecoder(bytes.NewReader(b)).Decode(&mwjer)
		if err != nil {
			return nil, err
		}
		bytesForMutation = mwjer.MutationLogEntry
	}

	// Now decode the map mutation as we need the value to either make the separate value
	// or to cross check against the real value
	var mut mapMutation
	err := json.NewDecoder(bytes.NewReader(bytesForMutation)).Decode(&mut)
	if err != nil {
		return nil, err
	}

	// Get bytes for the value
	if f.isSpecial() {
		valEntry, err = f.ValueFactory.CreateFromBytes(mwjer.OHInput)
		if err != nil {
			return nil, err
		}

		// Make sure the leaf hash actually matches the value as expected
		crossCheckLeafHash, err := valEntry.LeafHash()
		if err != nil {
			return nil, err
		}

		if !bytes.Equal(crossCheckLeafHash, LeafMerkleTreeHash(mut.Value)) {
			return nil, ErrVerificationFailed
		}
	} else {
		// otherwise just create the value
		valEntry, err = f.ValueFactory.CreateFromBytes(mut.Value)
		if err != nil {
			return nil, err
		}
	}

	// Finally, wrap the JsonEntry
	jsonEntry, err := JsonEntryFactory.CreateFromBytes(bytesForMutation)
	if err != nil {
		return nil, err
	}

	return &mutationEntry{LogEntry: jsonEntry, Value: valEntry}, nil
}

// Format returns the format needed to underlying requests to get-entries.
func (f *mutationEntryFactory) Format() string {
	// If the underlying value format is Json or RedactedJson, then we need to request
	// the special mutation format, else we should just request JSON, since the value
	// is included as raw bytes in the mutation entry.
	if f.isSpecial() {
		return "/xjson/mutation"
	} else {
		return "/xjson"
	}
}

type auditState struct {
	// Must be set
	Map *VerifiableMap

	// Current mutation log tree head
	MutLogHead *LogTreeHead

	// Audit function, called for each mutation
	MapAuditFunction MapAuditFunction

	// Factory to create values for entries
	EntryValueFactory VerifiableEntryFactory

	// Not set:
	Root            mapAuditNode // not a pointer so that we get good empty value
	MutLogHashStack [][]byte

	Size                 int64 // number of mutations processed, parallel arrays below
	MutationLogTreeHeads [][]byte
	MapTreeHeads         [][]byte
}

// Move the state of the audit forward to the specified size.
func (a *auditState) ProcessUntilAtLeast(ctx context.Context, size int64) error {
	// Do we need to do any work?
	if size > a.Size {
		// For now, always just fetch until head - else we'd be fetching one entry at a time
		mutLog := a.Map.MutationLog()

		// Get the lastest tree head for the mutation log
		mutLogHead, err := mutLog.VerifiedLatestTreeHead(a.MutLogHead)
		if err != nil {
			return err
		}

		// Save this off, we need to compare later
		lastRootHash := a.Root.CalcHash()

		// Perform audit of the mutation log, providing a special function to apply mutations
		// to our copy of the map
		err = mutLog.VerifyEntries(ctx, a.MutLogHead, mutLogHead, &mutationEntryFactory{ValueFactory: a.EntryValueFactory}, func(ctx context.Context, idx int64, entry VerifiableEntry) error {
			// Get the mutation
			mutationJson, err := entry.Data()
			if err != nil {
				return err
			}

			// Decode it into standard structure
			var mutation mapMutation
			err = json.Unmarshal(mutationJson, &mutation)
			if err != nil {
				return err
			}

			// Apply it to our copy of the map
			rh, err := addMutationToTree(&a.Root, &mutation)
			if err != nil {
				return err
			}

			// Keep our own copy of the mutation log hash stack so that we can
			// verify the mutation log heads as well.
			lh, err := entry.LeafHash()
			if err != nil {
				return err
			}

			// Apply to stack
			a.MutLogHashStack = append(a.MutLogHashStack, lh)
			for z := idx; (z & 1) == 1; z >>= 1 {
				a.MutLogHashStack = append(a.MutLogHashStack[:len(a.MutLogHashStack)-2], NodeMerkleTreeHash(a.MutLogHashStack[len(a.MutLogHashStack)-2], a.MutLogHashStack[len(a.MutLogHashStack)-1]))
			}

			// Save off current one
			headHash := a.MutLogHashStack[len(a.MutLogHashStack)-1]
			for z := len(a.MutLogHashStack) - 2; z >= 0; z-- {
				headHash = NodeMerkleTreeHash(a.MutLogHashStack[z], headHash)
			}

			// Now add both to our saved copy of the tree head log.
			a.MutationLogTreeHeads = append(a.MutationLogTreeHeads, headHash)
			a.MapTreeHeads = append(a.MapTreeHeads, rh)

			// Finally, if we actually made a change (ie the mutation did something)
			// then call the underlying audit function provided by the client.
			if a.MapAuditFunction != nil && !bytes.Equal(lastRootHash, rh) {
				me, ok := entry.(*mutationEntry)
				if !ok {
					return ErrVerificationFailed
				}

				err = a.MapAuditFunction(ctx, idx, mutation.Key, me.Value)
				if err != nil {
					return err
				}
			}

			// Save for next time
			lastRootHash = rh

			return nil
		})
		if err != nil {
			return err
		}

		// Save off mutation log for next run
		a.MutLogHead = mutLogHead
		a.Size = a.MutLogHead.TreeSize
	}

	if size > a.Size {
		return ErrVerificationFailed
	}

	return nil
}

// CheckTreeHeadEntry is the audit function that checks the actual tree head is correct
func (a *auditState) CheckTreeHeadEntry(ctx context.Context, idx int64, entry VerifiableEntry) error {
	// Get the tree head data
	treeHeadJson, err := entry.Data()
	if err != nil {
		return err
	}

	// Decode it into standard structure
	var mth mapHashResponse
	err = json.NewDecoder(bytes.NewReader(treeHeadJson)).Decode(&mth)
	if err != nil {
		return err
	}

	// Advance the state of the auditor to at least this size
	err = a.ProcessUntilAtLeast(ctx, mth.LogSTH.TreeSize)
	if err != nil {
		return err
	}

	// Check map root hash (subtract 1 from index since size 1 is the first meaningful)
	if !bytes.Equal(a.MapTreeHeads[mth.LogSTH.TreeSize-1], mth.MapHash) {
		return ErrVerificationFailed
	}

	// Check mutation log hash (subtract 1 from index since size 1 is the first meaningful)
	if !bytes.Equal(a.MutationLogTreeHeads[mth.LogSTH.TreeSize-1], mth.LogSTH.Hash) {
		return ErrVerificationFailed
	}

	// All good
	return nil
}

// MapAuditFunction is a function called by a map auditor after a MapMutation has been to
// an audited map, and verified to have been processsed correctly by the map. This function
// gives an opportunity for a map auditor to indicate success/failure of the audit based on
// other characteristics, such as correctness of the values of the entires.
// Note that this is only called if the mutation resulted in a change to the map root hash,
// so for example it is not called for a mutation that does not modify the value for a key,
// such as setting the same value again (that is already set), or updates based on a previous
// value where the previous value is not current.
// idx the index of the mutation - while this will always increase, there may be gaps per the
// reasons outlined above.
// key is the key that is being changed
// value (produced by VerifiableEntryFactory specified when creating the auditor) is the
//  value being set/deleted/modified.
type MapAuditFunction func(ctx context.Context, idx int64, key []byte, value VerifiableEntry) error

// VerifyMap (Experimental API surface, likely to change) is a utility method for auditors
// that wish to audit the full content of a map, as well as the map operation. This method
// will verify every entry in the TreeHeadLogTreeHead between prev and head - and to do so
// will retrieve *all* mutation entries from the underlying mutation log, and play them
// forward in an in-memory map copy.
//
// In addition to verifying the correct operation of the map itself, a client also specifies
// an auditFunc that is called for each set value operation that results in a change to the
// map itself. As such a client can also verify any property desired around the actual
// key/values themselves that are being manipulated. Note that not every mutation will result
// in a call to auditFunc - operations that result in no change to the map will not call
// the audit function.
//
// To verify all every log tree head entry, pass nil for prev, which will also bypass consistency proof checking. Head must not be nil.
//
// Example usage:
//
//	latestMapState, err := vmap.VerifiedLatestMapState(nil)
//	if err != nil {
//		...
//	}
//
//	err = vmap.VerifyMap(ctx, nil, latestMapState, continusec.RedactedJsonEntryFactory, func(ctx context.Context, idx int64, key []byte, value continusec.VerifiableEntry) error {
//		... // verify anything you like about the content
//		return nil
//	})
//	if err != nil {
//		...
//	}
//
// While suitable for small to medium maps, this requires the entire map be built in-memory
// which may not be suitable for larger systems that will have more complex requirements.
func (self *VerifiableMap) VerifyMap(ctx context.Context, prev *MapTreeState, head *MapTreeState, factory VerifiableEntryFactory, auditFunc MapAuditFunction) error {
	var prevLth *LogTreeHead
	if prev != nil {
		prevLth = &prev.TreeHeadLogTreeHead
	}

	if head == nil {
		return ErrNilTreeHead
	}

	return self.TreeHeadLog().VerifyEntries(ctx, prevLth, &head.TreeHeadLogTreeHead, JsonEntryFactory, (&auditState{
		Map:               self,
		MapAuditFunction:  auditFunc,
		EntryValueFactory: factory,
	}).CheckTreeHeadEntry)
}
