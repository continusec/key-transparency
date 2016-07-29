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
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"os"
	"strconv"

	"github.com/boltdb/bolt"
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
