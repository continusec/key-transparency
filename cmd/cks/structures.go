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

package main

import (
	"crypto/sha256"
	"math/big"

	"github.com/continusec/go-client/continusec"
)

// A Sig is the asn1 form of this.
type ECDSASignature struct {
	// R, S are as returned by ecdsa.Sign
	R, S *big.Int
}

// PublicKeyData is the data stored for a key in the Merkle Tree.
type PublicKeyData struct {
	// Sequence number, starting from 0, of different values for this key
	Sequence int64 `json:"sequence"`

	// PriorTreeSize is any prior tree size that had the value this key for Sequence - 1.
	PriorTreeSize int64 `json:"priorTreeSize"`

	// The plain text email address for which this key is valid
	Email string `json:"email"`

	// The public key data held for this key.
	PGPPublicKey []byte `json:"pgpPublicKey"`
}

// FollowedUserRecord is stored locally for each user that we follow. We don't bother
// persisting history in this record since we get that "for free" in our cache
type FollowedUserRecord struct {
	// The size of the map when this data was retreived
	MapSize int64

	// The key data retreived and verified - may be nil if none was present at that size
	KeyData *PublicKeyData

	// Not stored (since this is the key) but useful for downstream processing
	email string
}

// Tree size response from server, used for JSON deserialization.
type treeSizeResponse struct {
	TreeSize int64  `json:"tree_size"`
	Hash     []byte `json:"tree_hash"`
}

// Structure for gossip
type gossip struct {
	Signature           []byte `json:"sig"`
	TreeHeadLogTreehead []byte `json:"thlth"`
}

// GetEntryResult is the data returned when looking up data for an email address
type GetEntryResult struct {
	// VUFResult is the result of applying the VUF to the email address. In practice this is
	// the PKCS15 signature of the SHA256 hash of the email address. This must be verified by
	// the client.
	VUFResult []byte `json:"vufResult"`

	// AuditPath is the set of Merkle Tree nodes that should be applied along with this
	// value to produce the Merkle Tree root hash.
	AuditPath [][]byte `json:"auditPath"`

	// TreeSize is the size of the Merkle Tree for which this inclusion proof is valid.
	TreeSize int64 `json:"treeSize"`

	// PublicKeyValue is a redacted JSON for PublicKeyData field.
	PublicKeyValue []byte `json:"publicKeyValue"`
}

// Verify that this result is included in the given map state
func (ger *GetEntryResult) VerifyInclusion(ms *continusec.MapTreeState) error {
	x := sha256.Sum256(ger.VUFResult)
	return (&continusec.MapInclusionProof{
		TreeSize:  ger.TreeSize,
		AuditPath: ger.AuditPath,
		Value:     &continusec.RedactedJsonEntry{RedactedJsonBytes: ger.PublicKeyValue},
		Key:       x[:],
	}).Verify(&ms.MapTreeHead)
}
