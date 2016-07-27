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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"

	"golang.org/x/net/context"

	"github.com/continusec/objecthash"
)

// Head can be used where tree sizes are accepted to represent the latest tree size.
// Most typically this is used with TreeHead() calls where the latest tree size is not
// yet known.
const Head = int64(0)

var (
	// ErrNotAuthorized is returned when the request is understood, but there are no API access
	// rules specified that allow such access. Check the API Key and account number passed are correct,
	// and that you are trying to access the log/map with the appropriate name.
	//
	// Also have an administrator check the "Billing" page to ensure the billing settings are up to date, as this
	// error can also be indicative of an expired free trial, or an expired credit card.
	ErrNotAuthorized = errors.New("Unauthorized request. Check API key, account, log name and also billing settings.")

	// ErrInternalError is an unspecified error. Contact info@continusec.com if these persist.
	ErrInternalError = errors.New("Unspecified error.")

	// ErrInvalidRange is returned when an invalid index is specified in the request, for example
	// if a tree size is specified that is greater than the current size of the tree / map.
	ErrInvalidRange = errors.New("Invalid range requested.")

	// ErrNotFound is returned when the request is understood and authorized, however the underlying
	// map/log cannot be found. Check the name of the map/log and verify that you have already created it.
	// This is also returned if an inclusion proof is requested for a non-existent element.
	ErrNotFound = errors.New("Can't find log/map/entry. Check the log/map/entry is created.")

	// Verification of proof failed.
	ErrVerificationFailed = errors.New("ErrVerificationFailed")

	// Object may already exist
	ErrObjectConflict = errors.New("ErrObjectConflict")

	// A nil tree head was unexpectedly passed as input
	ErrNilTreeHead = errors.New("ErrNilTreeHead")

	// ErrNotAllEntriesReturned can occur if Json is requested, but the data on the server was
	// not stored in that manner. If in doubt, RawDataEntryFactory will always succeed regardless of input format.
	ErrNotAllEntriesReturned = errors.New("ErrNotAllEntriesReturned")
)

// LogAuditFunction is a function that is called for all matching log entries.
// Return non-nil to stop the audit.
type LogAuditFunction func(ctx context.Context, idx int64, entry VerifiableEntry) error

// MerkleTreeLeaf is an interface to represent any object that a Merkle Tree Leaf can be calculated for.
// This includes RawDataEntry, JsonEntry, RedactedJsonEntry, AddEntryResponse and MapHead.
type MerkleTreeLeaf interface {
	// LeafHash() returns the leaf hash for this object.
	LeafHash() ([]byte, error)
}

// UploadableEntry is an interface to represent an entry type that can be uploaded as a log entry or map value.
// This includes RawDataEntry, JsonEntry, RedactableJsonEntry.
type UploadableEntry interface {
	// DataForUpload returns the data that should be uploaded
	DataForUpload() ([]byte, error)
	// Format returns the format suffix that should be be appended to the PUT/POST API call
	Format() string
}

// VerifiableEntry is an interface that represents an entry returned from the log
type VerifiableEntry interface {
	// LeafHash() returns the leaf hash for this object.
	LeafHash() ([]byte, error)
	// Data() returns data suitable for downstream processing of this entry by your application.
	Data() ([]byte, error)
}

// VerifiableEntryFactory is an for instantiation of VerifiableEntries from bytes.
type VerifiableEntryFactory interface {
	// CreateFromBytes creates a new VerifiableEntry given these bytes from the server.
	CreateFromBytes(b []byte) (VerifiableEntry, error)
	// Format returns the format suffix that should be be appended to the GET call.
	Format() string
}

// AddEntryResponse represents a response from a call to add an entry to a log or map
type AddEntryResponse struct {
	// EntryLeafHash is the Merkle Tree Leaf hash of the item as added
	EntryLeafHash []byte
}

// LeafHash() returns the leaf hash for this object.
func (self *AddEntryResponse) LeafHash() ([]byte, error) {
	return self.EntryLeafHash, nil
}

// JsonEntry should used when entry MerkleTreeLeafs should be based on ObjectHash rather than the JSON bytes directly.
// Since there is no canonical encoding for JSON, it is useful to hash these objects in a more defined manner.
type JsonEntry struct {
	// The data to add
	JsonBytes []byte
	leafHash  []byte
}

// Data() returns data suitable for downstream processing of this entry by your application.
func (self *JsonEntry) Data() ([]byte, error) {
	return self.JsonBytes, nil
}

// DataForUpload returns the data that should be uploaded
func (self *JsonEntry) DataForUpload() ([]byte, error) {
	return self.JsonBytes, nil
}

// Format returns the format suffix should be be appended to the PUT/POST API call
func (self *JsonEntry) Format() string {
	return "/xjson"
}

// LeafHash() returns the leaf hash for this object.
func (self *JsonEntry) LeafHash() ([]byte, error) {
	if self.leafHash == nil {
		if len(self.JsonBytes) == 0 {
			self.leafHash = LeafMerkleTreeHash(nil)
		} else {
			var contents interface{}
			err := json.Unmarshal(self.JsonBytes, &contents)
			if err != nil {
				return nil, err
			}
			oh, err := objecthash.ObjectHashWithStdRedaction(contents)
			if err != nil {
				return nil, err
			}
			self.leafHash = LeafMerkleTreeHash(oh)
		}
	}
	return self.leafHash, nil
}

// JsonEntryFactoryImpl is a VerifiableEntryFactory that produces JsonEntry instances upon request.
type JsonEntryFactoryImpl struct{}

// CreateFromBytes creates a new VerifiableEntry given these bytes from the server.
func (self *JsonEntryFactoryImpl) CreateFromBytes(b []byte) (VerifiableEntry, error) {
	return &JsonEntry{JsonBytes: b}, nil
}

// Format returns the format suffix that should be be appended to the GET call.
func (self *JsonEntryFactoryImpl) Format() string {
	return "/xjson"
}

// JsonEntryFactory is an instance of JsonEntryFactoryImpl that is ready for use
var JsonEntryFactory = &JsonEntryFactoryImpl{}

// RawDataEntry represents a log/map entry where no special processing is performed, that is,
// the bytes specified are stored as-is, and are used as-is for input to the Merkle Tree leaf function.
type RawDataEntry struct {
	// The data to add
	RawBytes []byte
	leafHash []byte
}

// Data() returns data suitable for downstream processing of this entry by your application.
func (self *RawDataEntry) Data() ([]byte, error) {
	return self.RawBytes, nil
}

// DataForUpload returns the data that should be uploaded
func (self *RawDataEntry) DataForUpload() ([]byte, error) {
	return self.RawBytes, nil
}

// Format returns the format suffix should be be appended to the PUT/POST API call
func (self *RawDataEntry) Format() string {
	return ""
}

// LeafHash() returns the leaf hash for this object.
func (self *RawDataEntry) LeafHash() ([]byte, error) {
	if self.leafHash == nil {
		self.leafHash = LeafMerkleTreeHash(self.RawBytes)
	}
	return self.leafHash, nil
}

// RawDataEntryFactoryImpl is a VerifiableEntryFactory that produces JsonEntry instances upon request.
type RawDataEntryFactoryImpl struct{}

// CreateFromBytes creates a new VerifiableEntry given these bytes from the server.
func (self *RawDataEntryFactoryImpl) CreateFromBytes(b []byte) (VerifiableEntry, error) {
	return &RawDataEntry{RawBytes: b}, nil
}

// Format returns the format suffix that should be be appended to the GET call.
func (self *RawDataEntryFactoryImpl) Format() string {
	return ""
}

// RawDataFactory is an instance of RawDataEntryFactoryImpl that is ready for use
var RawDataEntryFactory = &RawDataEntryFactoryImpl{}

// RedactableJsonEntry  represents JSON data should be made Redactable by the server upon upload.
// ie change all dictionary values to be nonce-value tuples and control access to fields based on the API key used to make the request.
// This class is for entries that should be uploaded. Entries that are returned are of type RedactedJsonEntry.
type RedactableJsonEntry struct {
	// The data to add
	JsonBytes []byte
	leafHash  []byte
}

// DataForUpload returns the data that should be uploaded
func (self *RedactableJsonEntry) DataForUpload() ([]byte, error) {
	return self.JsonBytes, nil
}

// Format returns the format suffix should be be appended to the PUT/POST API call
func (self *RedactableJsonEntry) Format() string {
	return "/xjson/redactable"
}

// RedactedJsonEntry represents redacted entries as returned by the server.
// Not to be confused with RedactableJsonEntry that should be used to represent objects that
// should be made redactable by the server when uploaded.
type RedactedJsonEntry struct {
	// The data returned
	RedactedJsonBytes []byte
	shedBytes         []byte
	leafHash          []byte
}

// Data() returns data suitable for downstream processing of this entry by your application.
func (self *RedactedJsonEntry) Data() ([]byte, error) {
	if self.shedBytes == nil {
		var contents interface{}
		err := json.Unmarshal(self.RedactedJsonBytes, &contents)
		if err != nil {
			return nil, err
		}
		newContents, err := objecthash.UnredactableWithStdPrefix(contents)
		if err != nil {
			return nil, err
		}
		self.shedBytes, err = json.Marshal(newContents)
		if err != nil {
			return nil, err
		}
	}
	return self.shedBytes, nil
}

// LeafHash() returns the leaf hash for this object.
func (self *RedactedJsonEntry) LeafHash() ([]byte, error) {
	if self.leafHash == nil {
		if len(self.RedactedJsonBytes) == 0 {
			self.leafHash = LeafMerkleTreeHash(nil)
		} else {
			var contents interface{}
			err := json.Unmarshal(self.RedactedJsonBytes, &contents)
			if err != nil {
				return nil, err
			}
			oh, err := objecthash.ObjectHashWithStdRedaction(contents)
			if err != nil {
				return nil, err
			}
			self.leafHash = LeafMerkleTreeHash(oh)
		}
	}
	return self.leafHash, nil
}

// RedactedJsonEntryFactoryImpl is a VerifiableEntryFactory that produces RedactedJsonEntry instances upon request.
type RedactedJsonEntryFactoryImpl struct{}

// CreateFromBytes creates a new VerifiableEntry given these bytes from the server.
func (self *RedactedJsonEntryFactoryImpl) CreateFromBytes(b []byte) (VerifiableEntry, error) {
	return &RedactedJsonEntry{RedactedJsonBytes: b}, nil
}

// Format returns the format suffix that should be be appended to the GET call.
func (self *RedactedJsonEntryFactoryImpl) Format() string {
	return "/xjson"
}

// RedactedJsonEntryFactory is an instance of RedactedJsonEntryFactoryImpl that is ready for use
var RedactedJsonEntryFactory = &RedactedJsonEntryFactoryImpl{}

// LogTreeHead is a class for Tree Head as returned for a log with a given size.
type LogTreeHead struct {
	// TreeSize is the size of the tree for which the RootHash is valid
	TreeSize int64
	// RootHash is the root hash for log of size TreeSize
	RootHash []byte
}

// MapTreeHead is a class for Tree Head as returned for a Map with a given size.
type MapTreeHead struct {
	// RootHash is the root hash for map of size MutationLogTreeHead.TreeSize
	RootHash []byte

	// MutationLogTreeHead is the mutation log tree head for which this RootHash is valid
	MutationLogTreeHead LogTreeHead

	leafHash []byte
}

// TreeSize is a utility method to return the tree size of the underlying mutation log.
func (self *MapTreeHead) TreeSize() int64 {
	return self.MutationLogTreeHead.TreeSize
}

// LeafHash allows for this MapTreeHead to implement MerkleTreeLeaf which makes it
// convenient for use with inclusion proof checks against the TreeHead log.
func (self *MapTreeHead) LeafHash() ([]byte, error) {
	if self.leafHash == nil {
		oh, err := objecthash.ObjectHash(map[string]interface{}{
			"map_hash": base64.StdEncoding.EncodeToString(self.RootHash), // Our hashes are encoded as base64 in JSON, so use this as input to objecthash
			"mutation_log": map[string]interface{}{
				"tree_size": float64(self.TreeSize()),                                             // JSON knows only numbers, so sadly we pretend to be a float
				"tree_hash": base64.StdEncoding.EncodeToString(self.MutationLogTreeHead.RootHash), // Our hashes are encoded as base64 in JSON, so use this as input to objecthash
			},
		})
		if err != nil {
			return nil, err
		}
		self.leafHash = LeafMerkleTreeHash(oh)
	}
	return self.leafHash, nil
}

// MapTreeState represents the current state of a map, intended for persistence by callers.
// It combines the MapTreeHead which is the current state, with the LogTreeHead for the underlying
// tree head log which has been verified to include this MapTreeHead
type MapTreeState struct {
	// MapTreeHead is the root hash / mutation tree head for the map at this time.
	MapTreeHead MapTreeHead

	// TreeHeadLogTreeHead is a TreeHead for the Tree Head log, which contains this Map Tree Head.
	// The tree size in this log tree head may be different to that in the mutation log tree head.
	// The TreeSize of this MapTreeState is dictated by the tree size of the Mutation Log which the map root hash represents.
	TreeHeadLogTreeHead LogTreeHead
}

// TreeSize is a utility method for returning the tree size of the underlying map.
func (self *MapTreeState) TreeSize() int64 {
	return self.MapTreeHead.TreeSize()
}

// LogConsistencyProof is a class to represent a consistency proof for a given log.
type LogConsistencyProof struct {
	// AuditPath is the set of Merkle Tree Hashes needed to prove consistency
	AuditPath [][]byte

	// FirstSize is the size of the first tree
	FirstSize int64

	// SecondSize is the size of the second tree
	SecondSize int64
}

// Verify will verify that the consistency proof stored in this object can produce both the LogTreeHeads passed to this method.
func (self *LogConsistencyProof) Verify(first, second *LogTreeHead) error {
	if first.TreeSize != self.FirstSize {
		return ErrVerificationFailed
	}

	if second.TreeSize != self.SecondSize {
		return ErrVerificationFailed
	}

	if self.FirstSize < 1 {
		return ErrVerificationFailed
	}

	if self.FirstSize >= second.TreeSize {
		return ErrVerificationFailed
	}

	var proof [][]byte
	if isPow2(self.FirstSize) {
		proof = make([][]byte, 1+len(self.AuditPath))
		proof[0] = first.RootHash
		copy(proof[1:], self.AuditPath)
	} else {
		proof = self.AuditPath
	}

	fn, sn := self.FirstSize-1, second.TreeSize-1
	for 1 == (fn & 1) {
		fn >>= 1
		sn >>= 1
	}
	if len(proof) == 0 {
		return ErrVerificationFailed
	}
	fr := proof[0]
	sr := proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return ErrVerificationFailed
		}
		if (1 == (fn & 1)) || (fn == sn) {
			fr = NodeMerkleTreeHash(c, fr)
			sr = NodeMerkleTreeHash(c, sr)
			for !((fn == 0) || (1 == (fn & 1))) {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeMerkleTreeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return ErrVerificationFailed
	}

	if !bytes.Equal(first.RootHash, fr) {
		return ErrVerificationFailed
	}

	if !bytes.Equal(second.RootHash, sr) {
		return ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(fr) != 32 {
		return ErrVerificationFailed
	}
	if len(sr) != 32 {
		return ErrVerificationFailed
	}

	// all clear
	return nil
}

// LogInclusionProof is a class to represent a consistency proof for a given log.
type LogInclusionProof struct {
	// AuditPath is the set of Merkle Tree Hashes needed to prove inclusion
	AuditPath [][]byte

	// TreeSize is the size of the tree for which this proof is valid
	TreeSize int64

	// LeafIndex is the index of this leaf within the tree
	LeafIndex int64

	// LeafHash is the Merkle Tree Leaf hash for which this proof is based
	LeafHash []byte
}

// Verify verifies an inclusion proof against a LogTreeHead
func (self *LogInclusionProof) Verify(head *LogTreeHead) error {
	if self.TreeSize != head.TreeSize {
		return ErrVerificationFailed
	}
	if self.LeafIndex >= self.TreeSize {
		return ErrVerificationFailed
	}
	if self.LeafIndex < 0 {
		return ErrVerificationFailed
	}

	fn, sn := self.LeafIndex, self.TreeSize-1
	r := self.LeafHash
	for _, p := range self.AuditPath {
		if (fn == sn) || ((fn & 1) == 1) {
			r = NodeMerkleTreeHash(p, r)
			for !((fn == 0) || ((fn & 1) == 1)) {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeMerkleTreeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return ErrVerificationFailed
	}
	if !bytes.Equal(r, head.RootHash) {
		return ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(r) != 32 {
		return ErrVerificationFailed
	}

	// all clear
	return nil
}

// MapInclusionProof represents the response for getting an entry from a map. It contains both the value itself,
// as well as an inclusion proof for how that value fits into the map root hash.
type MapInclusionProof struct {
	// Key is the key for which this inclusion proof is valid
	Key []byte

	// Value represents the entry for which this proof is valid
	Value VerifiableEntry

	// AuditPath is the set of Merkle Tree Hashes needed to prove consistency
	AuditPath [][]byte

	// TreeSize is the size of the tree for which this proof is valid
	TreeSize int64
}

// Verify verifies an inclusion proof against a MapTreeHead
func (self *MapInclusionProof) Verify(head *MapTreeHead) error {
	if self.TreeSize != head.MutationLogTreeHead.TreeSize {
		return ErrVerificationFailed
	}

	kp := ConstructMapKeyPath(self.Key)
	t, err := self.Value.LeafHash()
	if err != nil {
		return err
	}
	for i := len(kp) - 1; i >= 0; i-- {
		p := self.AuditPath[i]
		if p == nil {
			p = defaultLeafValues[i+1]
		}

		if kp[i] {
			t = NodeMerkleTreeHash(p, t)
		} else {
			t = NodeMerkleTreeHash(t, p)
		}
	}

	if !bytes.Equal(t, head.RootHash) {
		return ErrVerificationFailed
	}

	// should not happen, but guarding anyway
	if len(t) != 32 {
		return ErrVerificationFailed
	}

	// all clear
	return nil
}

// ConstructMapKeyPath returns the path in the tree for a given key. Specifically it takes
// the SHA256 hash of the key, and then returns a big-endian slice of booleans representing
// the equivalent path in the tree.
func ConstructMapKeyPath(key []byte) []bool {
	h := sha256.Sum256(key)
	nm := len(h) * 8
	rv := make([]bool, nm)
	for i, b := range h {
		for j := uint(0); j < 8; j++ {
			if ((b >> j) & 1) == 1 {
				rv[(uint(i)<<3)+7-j] = true
			}
		}
	}
	return rv
}

var defaultLeafValues = GenerateMapDefaultLeafValues()

// GenerateMapDefaultLeafValues returns a copy of the default leaf values for any empty nodes
// in a proof. This can be useful for implementations that verify inclusion proofs of Map Values.
func GenerateMapDefaultLeafValues() [][]byte {
	rv := make([][]byte, 257)
	rv[256] = LeafMerkleTreeHash(nil)
	for i := 255; i >= 0; i-- {
		rv[i] = NodeMerkleTreeHash(rv[i+1], rv[i+1])
	}
	return rv
}

// NodeMerkleTreeHash is a utility function for calculating the Merkle Tree Hash for a node.
func NodeMerkleTreeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// LeafMerkleTreeHash is a utility function for calculating the Merkle Tree Hash for a leaf.
func LeafMerkleTreeHash(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(b)
	return h.Sum(nil)
}

func isPow2(n int64) bool {
	return calcK(n+1) == n
}

func calcK(n int64) int64 {
	k := int64(1)
	for (k << 1) < n {
		k <<= 1
	}
	return k
}
