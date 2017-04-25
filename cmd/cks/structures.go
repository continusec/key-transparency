/*
   Copyright 2017 Continusec Pty Ltd

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
	"time"

	"github.com/continusec/key-transparency/pb"
)

// FollowedUserRecord is stored locally for each user that we follow. We don't bother
// persisting history in this record since we get that "for free" in our cache
type FollowedUserRecord struct {
	// The size of the map when this data was retreived
	MapSize int64

	// The key data retreived and verified - may be nil if none was present at that size
	KeyData *pb.VersionedKeyData

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

// UpdateResult is something we save off locally for each entry that we have added.
type UpdateResult struct {
	// Email address that this was added for
	Email string

	// Mutation log entry as returned by the server
	MutationLeafHash []byte

	// sha256 of the value set
	ValueHash []byte

	// -1 means unknown
	LeafIndex int64

	// -1 means unknown. -2 means never took effect
	UserSequence int64

	// Timestamp when written
	Timestamp time.Time
}

/*
// Verify that this result is included in the given map state
func (ger *GetEntryResult) VerifyInclusion(ms *verifiabledatastructures.MapTreeState) error {
	x := sha256.Sum256(ger.VUFResult)
	v, err := verifiabledatastructures.CreateJSONLeafData(ger.PublicKeyValue)
	if err != nil {
		return err
	}
	return verifiabledatastructures.VerifyMapInclusionProof(&vpb.MapGetValueResponse{
		TreeSize:  ger.TreeSize,
		AuditPath: ger.AuditPath,
		Value:     v,
	}, x[:], ms.MapTreeHead)
}
*/
