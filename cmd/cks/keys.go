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
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"

	"github.com/boltdb/bolt"
	"github.com/continusec/key-transparency/pb"
	"github.com/continusec/verifiabledatastructures"
)

// Get public key data for user in a particular map state. May return nil.
func getVerifiedValueForMapState(ctx context.Context, key string, ms *verifiabledatastructures.MapTreeState) (*pb.VersionedKeyData, error) {
	client, err := getKTClient("")
	if err != nil {
		return nil, err
	}

	res, err := client.MapVUFGetValue(ctx, &pb.MapVUFGetKeyRequest{
		Key:      []byte(key),
		TreeSize: ms.TreeSize(),
	})
	if err != nil {
		return nil, err
	}

	err = verifiabledatastructures.VerifyMapInclusionProof(res.MapResponse, res.VufResult, ms.MapTreeHead)
	if err != nil {
		return nil, err
	}

	err = validateVufResult(key, res.VufResult)
	if err != nil {
		return nil, err
	}

	// Verify the extra data matches leaf input?
	err = verifiabledatastructures.ValidateJSONLeafData(ctx, res.MapResponse.Value)
	if err != nil {
		return nil, err
	}

	if len(res.MapResponse.Value.ExtraData) == 0 { // it's ok to get an empty result
		return nil, nil
	}

	data, err := verifiabledatastructures.ShedRedactedJSONFields(res.MapResponse.Value.ExtraData)
	if err != nil {
		return nil, err
	}

	var pkd pb.VersionedKeyData
	err = json.NewDecoder(bytes.NewReader(data)).Decode(&pkd)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(pkd.Key, []byte(key)) {
		return nil, errors.New("wrong email address stored against user")
	}

	return &pkd, nil
}

// Change the FollowedUserRecord for a followed user to be result that matches this map state
func updateKeyToMapState(db *bolt.DB, emailAddress string, ms *verifiabledatastructures.MapTreeState) error {
	pkd, err := getVerifiedValueForMapState(context.Background(), emailAddress, ms)
	if err != nil {
		return err
	}
	buffer := &bytes.Buffer{}
	err = gob.NewEncoder(buffer).Encode(&FollowedUserRecord{
		MapSize: ms.TreeSize(),
		KeyData: pkd,
	})
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("keys")).Put([]byte(emailAddress), buffer.Bytes())
	})
}

// Update all followed user records
func updateKeysToMapState(db *bolt.DB, ms *verifiabledatastructures.MapTreeState) error {
	users, err := getAllFollowedUsers(db)
	if err != nil {
		return err
	}
	for _, fur := range users {
		err = updateKeyToMapState(db, fur.email, ms)
		if err != nil {
			return err
		}
	}
	return nil
}

// Return a list of FollowedUserRecord for a user from newest (current to mapState) back to
// user sequence seqToStopAt. Pass -1 to go back through all.
func getHistoryForUser(emailAddress string, seqToStopAt int64, mapState *verifiabledatastructures.MapTreeState) ([]*FollowedUserRecord, error) {
	vmap, err := getMap()
	if err != nil {
		return nil, err
	}

	rv := make([]*FollowedUserRecord, 0)

	done := false
	expectedSeq := int64(-10)
	ctx := context.Background()
	for !done {
		pkd, err := getVerifiedValueForMapState(ctx, emailAddress, mapState)
		if err != nil {
			return nil, err
		}
		if pkd == nil {
			if expectedSeq >= 0 {
				return nil, errors.New("unable to find record for user")
			}
			done = true
		} else {
			if expectedSeq != -10 {
				if pkd.Sequence != expectedSeq {
					return nil, errors.New("unexpected user sequence number returned for user record (1)")
				}
			}
			expectedSeq = pkd.Sequence - 1
			if expectedSeq < -1 {
				return nil, errors.New("unexpected user sequence number returned for user record (2)")
			}

			rv = append(rv, &FollowedUserRecord{
				KeyData: pkd,
				MapSize: mapState.TreeSize(),
			})

			if pkd.PriorTreeSize == 0 {
				done = true
			} else {
				if pkd.Sequence <= seqToStopAt {
					done = true
				} else {
					mapState, err = vmap.VerifiedMapState(context.Background(), mapState, pkd.PriorTreeSize)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return rv, nil
}
