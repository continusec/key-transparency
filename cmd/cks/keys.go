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
	"encoding/gob"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/boltdb/bolt"
	"github.com/continusec/verifiabledatastructures/client"
)

// Get public key data for user in a particular map state. May return nil.
func getVerifiedValueForMapState(key string, ms *client.MapTreeState) (*PublicKeyData, error) {
	res, err := getValForEmail(key, ms.TreeSize())
	if err != nil {
		return nil, err
	}

	err = res.VerifyInclusion(ms)
	if err != nil {
		return nil, err
	}

	err = validateVufResult(key, res.VUFResult)
	if err != nil {
		return nil, err
	}

	if len(res.PublicKeyValue) == 0 { // it's ok to get an empty result
		return nil, nil
	}
	data, err := client.ShedRedactedJSONFields(res.PublicKeyValue)
	if err != nil {
		return nil, err
	}

	var pkd PublicKeyData
	err = json.NewDecoder(bytes.NewReader(data)).Decode(&pkd)
	if err != nil {
		return nil, err
	}

	if pkd.Email != key {
		return nil, errors.New("Wrong email address stored against user.")
	}

	return &pkd, nil
}

// Change the FollowedUserRecord for a followed user to be result that matches this map state
func updateKeyToMapState(db *bolt.DB, emailAddress string, ms *client.MapTreeState) error {
	pkd, err := getVerifiedValueForMapState(emailAddress, ms)
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
func updateKeysToMapState(db *bolt.DB, ms *client.MapTreeState) error {
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
func getHistoryForUser(emailAddress string, seqToStopAt int64, mapState *client.MapTreeState) ([]*FollowedUserRecord, error) {
	vmap, err := getMap()
	if err != nil {
		return nil, err
	}

	rv := make([]*FollowedUserRecord, 0)

	done := false
	expectedSeq := int64(-10)
	for !done {
		pkd, err := getVerifiedValueForMapState(emailAddress, mapState)
		if err != nil {
			return nil, err
		}
		if pkd == nil {
			if expectedSeq >= 0 {
				return nil, errors.New("Unable to find record for user.")
			}
			done = true
		} else {
			if expectedSeq != -10 {
				if pkd.Sequence != expectedSeq {
					return nil, errors.New("Unexpected user sequence number returned for user record (1).")
				}
			}
			expectedSeq = pkd.Sequence - 1
			if expectedSeq < -1 {
				return nil, errors.New("Unexpected user sequence number returned for user record (2).")
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
					mapState, err = vmap.VerifiedMapState(mapState, pkd.PriorTreeSize)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return rv, nil
}

// Get unverified value for email from server
func getValForEmail(emailAddress string, treeSize int64) (*GetEntryResult, error) {
	server, err := getServer()
	if err != nil {
		return nil, err
	}

	url := server + "/v2/publicKey/" + emailAddress + "/at/" + strconv.Itoa(int(treeSize))

	contents, err := doGet(url)
	if err != nil {
		return nil, err
	}

	var ger GetEntryResult
	err = json.Unmarshal(contents, &ger)
	if err != nil {
		return nil, err
	}

	return &ger, nil
}
