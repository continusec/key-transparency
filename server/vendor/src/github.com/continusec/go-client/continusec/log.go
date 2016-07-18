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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/net/context"
)

// VerifiableLog is an object used to interact with Verifiable Logs. To construct this
// object, call NewClient(...).VerifiableLog("logname")
type VerifiableLog struct {
	client *Client
	path   string
}

type addEntryResponse struct {
	Number int64  `json:"leaf_index"`
	Hash   []byte `json:"leaf_hash"`
}

type treeSizeResponse struct {
	TreeSize int64  `json:"tree_size"`
	Hash     []byte `json:"tree_hash"`
}

type consistencyResponse struct {
	First  int64    `json:"first_tree_size"`
	Second int64    `json:"second_tree_size"`
	Proof  [][]byte `json:"proof"`
}

type entryResponse struct {
	Number int64  `json:"leaf_index"`
	Hash   []byte `json:"leaf_hash"`
	Data   []byte `json:"leaf_data"`
}

type getEntriesResponse struct {
	Entries []*entryResponse `json:"entries"`
}

type inclProofResp struct {
	Number   int64    `json:"leaf_index"`
	TreeSize int64    `json:"tree_size"`
	Proof    [][]byte `json:"proof"`
}

// Create will send an API call to create a new log with the name specified when the
// VerifiableLog object was instantiated.
func (self *VerifiableLog) Create() error {
	_, _, err := self.client.makeRequest("PUT", self.path, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// Destroy will send an API call to delete this log - this operation removes it permanently,
// and renders the name unusable again within the same account, so please use with caution.
func (self *VerifiableLog) Destroy() error {
	_, _, err := self.client.makeRequest("DELETE", self.path, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// Add will send an API call to add the specified entry to the log. If the exact entry
// already exists in the log, it will not be added a second time.
// Returns an AddEntryResponse which includes the leaf hash, whether it is a duplicate or not. Note that the
// entry is sequenced in the underlying log in an asynchronous fashion, so the tree size
// will not immediately increase, and inclusion proof checks will not reflect the new entry
// until it is sequenced.
func (self *VerifiableLog) Add(e UploadableEntry) (*AddEntryResponse, error) {
	data, err := e.DataForUpload()
	if err != nil {
		return nil, err
	}
	contents, _, err := self.client.makeRequest("POST", self.path+"/entry"+e.Format(), data, nil)
	if err != nil {
		return nil, err
	}
	var aer addEntryResponse
	err = json.Unmarshal(contents, &aer)
	if err != nil {
		return nil, err
	}
	return &AddEntryResponse{EntryLeafHash: aer.Hash}, nil
}

// TreeHead returns tree root hash for the log at the given tree size. Specify continusec.Head
// to receive a root hash for the latest tree size.
func (self *VerifiableLog) TreeHead(treeSize int64) (*LogTreeHead, error) {
	contents, _, err := self.client.makeRequest("GET", self.path+fmt.Sprintf("/tree/%d", treeSize), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr treeSizeResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &LogTreeHead{
		TreeSize: cr.TreeSize,
		RootHash: cr.Hash,
	}, nil
}

// InclusionProof will return a proof the the specified MerkleTreeLeaf is included in the
// log. The proof consists of the index within the log that the entry is stored, and an
// audit path which returns the corresponding leaf nodes that can be applied to the input
// leaf hash to generate the root tree hash for the log.
//
// Most clients instead use VerifyInclusion which additionally verifies the returned proof.
func (self *VerifiableLog) InclusionProof(treeSize int64, leaf MerkleTreeLeaf) (*LogInclusionProof, error) {
	mtlHash, err := leaf.LeafHash()
	if err != nil {
		return nil, err
	}
	contents, _, err := self.client.makeRequest("GET", self.path+fmt.Sprintf("/tree/%d/inclusion/h/%s", treeSize, hex.EncodeToString(mtlHash)), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr inclProofResp
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &LogInclusionProof{
		LeafHash:  mtlHash,
		LeafIndex: cr.Number,
		AuditPath: cr.Proof,
		TreeSize:  cr.TreeSize,
	}, nil
}

// VerifyInclusion will fetch a proof the the specified MerkleTreeHash is included in the
// log and verify that it can produce the root hash in the specified LogTreeHead.
func (self *VerifiableLog) VerifyInclusion(head *LogTreeHead, leaf MerkleTreeLeaf) error {
	proof, err := self.InclusionProof(head.TreeSize, leaf)
	if err != nil {
		return err
	}

	err = proof.Verify(head)
	if err != nil {
		return err
	}

	// All good
	return nil
}

// InclusionProofByIndex will return an inclusion proof for a specified tree size and leaf index.
// This is not used by typical clients, however it can be useful for certain audit operations and debugging tools.
// The LogInclusionProof returned by this method will not have the LeafHash filled in and as such will fail to verify.
//
// Typical clients will instead use VerifyInclusionProof().
func (self *VerifiableLog) InclusionProofByIndex(treeSize, leafIndex int64) (*LogInclusionProof, error) {
	contents, _, err := self.client.makeRequest("GET", self.path+fmt.Sprintf("/tree/%d/inclusion/%d", treeSize, leafIndex), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr inclProofResp
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &LogInclusionProof{
		LeafHash:  nil,
		LeafIndex: cr.Number,
		AuditPath: cr.Proof,
		TreeSize:  cr.TreeSize,
	}, nil
}

// ConsistencyProof returns an audit path which contains the set of Merkle Subtree hashes
// that demonstrate how the root hash is calculated for both the first and second tree sizes.
//
// Most clients instead use VerifyInclusionProof which additionally verifies the returned proof.
func (self *VerifiableLog) ConsistencyProof(first, second int64) (*LogConsistencyProof, error) {
	contents, _, err := self.client.makeRequest("GET", self.path+fmt.Sprintf("/tree/%d/consistency/%d", second, first), nil, nil)
	if err != nil {
		return nil, err
	}
	var cr consistencyResponse
	err = json.Unmarshal(contents, &cr)
	if err != nil {
		return nil, err
	}
	return &LogConsistencyProof{
		AuditPath:  cr.Proof,
		FirstSize:  cr.First,
		SecondSize: cr.Second,
	}, nil
}

// VerifyConsistency takes two tree heads, retrieves a consistency proof, verifies it,
// and returns the result. The two tree heads may be in either order (even equal), but both must be greater than zero and non-nil.
func (self *VerifiableLog) VerifyConsistency(a, b *LogTreeHead) error {
	if a == nil || b == nil || a.TreeSize <= 0 || b.TreeSize <= 0 {
		return ErrVerificationFailed
	}

	// Special case being equal
	if a.TreeSize == b.TreeSize {
		if !bytes.Equal(a.RootHash, b.RootHash) {
			return ErrVerificationFailed
		}
		// All good
		return nil
	}

	// If wrong order, swap 'em
	if a.TreeSize > b.TreeSize {
		a, b = b, a
	}

	proof, err := self.ConsistencyProof(a.TreeSize, b.TreeSize)
	if err != nil {
		return err
	}
	err = proof.Verify(a, b)
	if err != nil {
		return err
	}

	// All good
	return nil
}

// Entry returns the entry stored for the given index using the passed in factory to instantiate the entry.
// This is normally one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
// If the entry was stored using one of the ObjectHash formats, then the data returned by a RawDataEntryFactory,
// then the object hash itself is returned as the contents. To get the data itself, use JsonEntryFactory.
func (self *VerifiableLog) Entry(idx int64, factory VerifiableEntryFactory) (VerifiableEntry, error) {
	contents, _, err := self.client.makeRequest("GET", self.path+fmt.Sprintf("/entry/%d", idx)+factory.Format(), nil, nil)
	if err != nil {
		return nil, err
	}
	rv, err := factory.CreateFromBytes(contents)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

// Entries batches requests to fetch entries from the server and returns a channel with the data
// for each entry. Close the context passed to terminate early if desired. If an error is
// encountered, the channel will be closed early before all items are returned.
//
// factory is normally one of one of RawDataEntryFactory, JsonEntryFactory or RedactedJsonEntryFactory.
func (self *VerifiableLog) Entries(ctx context.Context, start, end int64, factory VerifiableEntryFactory) <-chan VerifiableEntry {
	rv := make(chan VerifiableEntry)
	go func() {
		defer close(rv)
		batchSize := int64(500)
		for start < end {
			lastToFetch := start + batchSize
			if lastToFetch > end {
				lastToFetch = end
			}

			contents, _, err := self.client.makeRequest("GET", self.path+fmt.Sprintf("/entries/%d-%d%s", start, lastToFetch, factory.Format()), nil, nil)
			if err != nil {
				return
			}

			var ger getEntriesResponse
			err = json.Unmarshal(contents, &ger)
			if err != nil {
				return
			}

			gotOne := false
			for _, e := range ger.Entries {
				if e.Number == start { // good!
					ve, err := factory.CreateFromBytes(e.Data)
					if err != nil {
						return
					}
					select {
					case <-ctx.Done():
						return
					case rv <- ve:
						start++
						gotOne = true
					}
				} else {
					return
				}
			}
			// if we didn't get anything new e.g. wrong type of data factory is a common culprit
			if !gotOne {
				return
			}
		}
	}()
	return rv
}

// BlockUntilPresent blocks until the log is able to produce a LogTreeHead that includes the
// specified MerkleTreeLeaf. This polls TreeHead() and InclusionProof() until such time as a new
// tree hash is produced that includes the given MerkleTreeLeaf. Exponential back-off is used
// when no new tree hash is available.
//
// This is intended for test use.
func (self *VerifiableLog) BlockUntilPresent(leaf MerkleTreeLeaf) (*LogTreeHead, error) {
	lastHead := int64(-1)
	timeToSleep := time.Second
	for {
		lth, err := self.TreeHead(Head)
		if err != nil {
			return nil, err
		}
		if lth.TreeSize > lastHead {
			lastHead = lth.TreeSize
			err = self.VerifyInclusion(lth, leaf)
			switch err {
			case nil: // we found it
				return lth, nil
			case ErrNotFound:
				// no good, continue
			default:
				return nil, err
			}
			// since we got a new tree head, reset sleep time
			timeToSleep = time.Second
		} else {
			// no luck, snooze a bit longer
			timeToSleep *= 2
		}
		time.Sleep(timeToSleep)
	}
}

// VerifiedLatestTreeHead calls VerifiedTreeHead() with Head to fetch the latest tree head,
// and additionally verifies that it is newer than the previously passed tree head.
// For first use, pass nil to skip consistency checking.
func (self *VerifiableLog) VerifiedLatestTreeHead(prev *LogTreeHead) (*LogTreeHead, error) {
	head, err := self.VerifiedTreeHead(prev, Head)
	if err != nil {
		return nil, err
	}

	// If "newest" is actually older (but consistent), catch and return the previous. While the log should not
	// normally go backwards, it is reasonable that a distributed system may not be entirely up to date immediately.
	if prev != nil {
		if head.TreeSize <= prev.TreeSize {
			return prev, nil
		}
	}

	// All good
	return head, nil
}

// VerifiedTreeHead is a utility method to fetch a LogTreeHead and verifies that it is consistent with
// a tree head earlier fetched and persisted. For first use, pass nil for prev, which will
// bypass consistency proof checking. Tree size may be older or newer than the previous head value.
//
// Clients typically use VerifyLatestTreeHead().
func (self *VerifiableLog) VerifiedTreeHead(prev *LogTreeHead, treeSize int64) (*LogTreeHead, error) {
	// special case returning the value we already have
	if treeSize != 0 && prev != nil && prev.TreeSize == treeSize {
		return prev, nil
	}

	head, err := self.TreeHead(treeSize)
	if err != nil {
		return nil, err
	}

	if prev != nil {
		err = self.VerifyConsistency(prev, head)
		if err != nil {
			return nil, err
		}
	}

	return head, nil
}

// VerifySuppliedInclusionProof is a utility method that fetches any required tree heads that are needed
// to verify a supplied log inclusion proof. Additionally it will ensure that any fetched tree heads are consistent
// with any prior supplied LogTreeHead (which may be nil, to skip consistency checks).
//
// Upon success, the LogTreeHead returned is the one used to verify the inclusion proof - it may be newer or older than the one passed in.
// In either case, it will have been verified as consistent.
func (self *VerifiableLog) VerifySuppliedInclusionProof(prev *LogTreeHead, proof *LogInclusionProof) (*LogTreeHead, error) {
	headForInclProof, err := self.VerifiedTreeHead(prev, proof.TreeSize)
	if err != nil {
		return nil, err
	}

	err = proof.Verify(headForInclProof)
	if err != nil {
		return nil, err
	}

	// all clear
	return headForInclProof, nil
}

// VerifyEntries is a utility method for auditors that wish to audit the full content of
// a log, as well as the log operation. This method will retrieve all entries in batch from
// the log between the passed in prev and head LogTreeHeads, and ensure that the root hash in head can be confirmed to accurately represent
// the contents of all of the log entries retrieved. To start at entry zero, pass nil for prev, which will also bypass consistency proof checking. Head must not be nil.
func (self *VerifiableLog) VerifyEntries(ctx context.Context, prev *LogTreeHead, head *LogTreeHead, factory VerifiableEntryFactory, auditFunc AuditFunction) error {
	if head == nil {
		return ErrNilTreeHead
	}

	if prev != nil && head.TreeSize <= prev.TreeSize {
		return nil
	}

	if head.TreeSize < 1 {
		return nil
	}

	merkleTreeStack := make([][]byte, 0)
	idx := int64(0)
	if prev != nil && prev.TreeSize > 0 {
		idx = prev.TreeSize
		p, err := self.InclusionProofByIndex(prev.TreeSize+1, prev.TreeSize)
		if err != nil {
			return err
		}
		var firstHash []byte
		for _, b := range p.AuditPath {
			if firstHash == nil {
				firstHash = b
			} else {
				firstHash = NodeMerkleTreeHash(b, firstHash)
			}
		}
		if !bytes.Equal(firstHash, prev.RootHash) {
			return ErrVerificationFailed
		}
		if len(firstHash) != 32 {
			return ErrVerificationFailed
		}
		for i := len(p.AuditPath) - 1; i >= 0; i-- {
			merkleTreeStack = append(merkleTreeStack, p.AuditPath[i])
		}
	}

	ourCtx, canc := context.WithCancel(ctx)
	defer canc()
	for entry := range self.Entries(ourCtx, idx, head.TreeSize, factory) {
		// audit
		err := auditFunc(idx, entry)
		if err != nil {
			return err
		}

		mtlHash, err := entry.LeafHash()
		if err != nil {
			return err
		}

		merkleTreeStack = append(merkleTreeStack, mtlHash)
		for z := idx; (z & 1) == 1; z >>= 1 {
			merkleTreeStack = append(merkleTreeStack[:len(merkleTreeStack)-2], NodeMerkleTreeHash(merkleTreeStack[len(merkleTreeStack)-2], merkleTreeStack[len(merkleTreeStack)-1]))
		}

		idx++
	}

	if idx != head.TreeSize {
		return ErrNotAllEntriesReturned
	}

	if len(merkleTreeStack) == 0 {
		return ErrVerificationFailed
	}

	headHash := merkleTreeStack[len(merkleTreeStack)-1]
	for z := len(merkleTreeStack) - 2; z >= 0; z-- {
		headHash = NodeMerkleTreeHash(merkleTreeStack[z], headHash)
	}

	if !bytes.Equal(headHash, head.RootHash) {
		return ErrVerificationFailed
	}
	if len(headHash) != 32 {
		return ErrVerificationFailed
	}

	// all clear
	return nil
}
