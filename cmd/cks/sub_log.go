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
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"os"
	"strconv"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

// List all updates that we've initiated from our client
func listUpdates(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 0 {
		return errors.New("unexpected arguments")
	}

	results := make([][2][]byte, 0)
	gotOne := func(k, v []byte) error {
		results = append(results, [2][]byte{copySlice(k), copySlice(v)})
		return nil
	}
	err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("updates")).ForEach(func(k, v []byte) error { return gotOne(k, v) })
	})
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Email", "Value Hash", "Timestamp", "Mutation Log Entry", "Map Sequence", "User Sequence"})

	for _, r := range results {
		v := r[1]

		var ur UpdateResult
		err := gob.NewDecoder(bytes.NewReader(v)).Decode(&ur)
		if err != nil {
			return err
		}

		var mutSeq, userSeq string

		switch ur.LeafIndex {
		case -1:
			mutSeq = "Not yet sequenced"
		default:
			mutSeq = strconv.Itoa(int(ur.LeafIndex))

			switch ur.UserSequence {
			case -1:
				userSeq = "Not yet sequenced"
			case -2:
				userSeq = "Conflict - not sequenced"
			default:
				userSeq = strconv.Itoa(int(ur.UserSequence))
			}
		}

		table.Append([]string{
			ur.Email,
			base64.StdEncoding.EncodeToString(ur.ValueHash),
			ur.Timestamp.String()[:19],
			base64.StdEncoding.EncodeToString(ur.MutationLeafHash),
			mutSeq,
			userSeq,
		})
	}

	table.Render()
	return nil
}

// Update any updates that we don't have status for
func checkUpdateListForNewness(db *bolt.DB, ms *continusec.MapTreeState) error {
	results := make([][2][]byte, 0)
	gotOne := func(k, v []byte) error {
		results = append(results, [2][]byte{copySlice(k), copySlice(v)})
		return nil
	}
	err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("updates")).ForEach(func(k, v []byte) error { return gotOne(k, v) })
	})
	if err != nil {
		return err
	}
	for _, r := range results {
		k := r[0]
		v := r[1]

		var ur UpdateResult
		err := gob.NewDecoder(bytes.NewReader(v)).Decode(&ur)
		if err != nil {
			return err
		}

		if ur.LeafIndex == -1 {
			vmap, err := getMap()
			if err != nil {
				return err
			}
			proof, err := vmap.MutationLog().InclusionProof(ms.TreeSize(), &continusec.AddEntryResponse{EntryLeafHash: ur.MutationLeafHash})
			if err != nil {
				// pass, don't return err as it may not have been sequenced yet
			} else {
				err = proof.Verify(&ms.MapTreeHead.MutationLogTreeHead)
				if err != nil {
					return err
				}

				ur.LeafIndex = proof.LeafIndex

				// Next, check if the value took effect - remember to add 1 to the leaf index, e.g. mutation 6 is tree size 7
				mapStateForMut, err := vmap.VerifiedMapState(ms, proof.LeafIndex+1)
				if err != nil {
					return err
				}

				// See what we can get in that map state
				pkd, err := getVerifiedValueForMapState(ur.Email, mapStateForMut)
				if err != nil {
					return err
				}

				// This ought not happen - we could have conflicted with another, but not empty.
				if pkd == nil {
					return errors.New("Verification error, map says that no public key data exists, even though the mutation has sequenced")
				}

				// Now, see if we wrote the value we wanted
				vh := sha256.Sum256(pkd.PGPPublicKey)
				if bytes.Equal(vh[:], ur.ValueHash) {
					ur.UserSequence = pkd.Sequence
				} else {
					ur.UserSequence = -2
				}

				buffer := &bytes.Buffer{}
				err = gob.NewEncoder(buffer).Encode(ur)
				if err != nil {
					return err
				}

				err = db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte("updates")).Put(k, buffer.Bytes())
				})

				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
