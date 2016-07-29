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
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"os"
	"strconv"

	"github.com/boltdb/bolt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

// List all followed users
func listUsers(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 0 {
		return errors.New("unexpected arguments")
	}

	users, err := getAllFollowedUsers(db)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Email", "Value Hash", "User Sequence", "Last Updated"})
	for _, fur := range users {
		seq := "No key found"
		valS := "(none)"

		if fur.KeyData != nil {
			seq = strconv.Itoa(int(fur.KeyData.Sequence))
			vh := sha256.Sum256(fur.KeyData.PGPPublicKey)
			valS = base64.StdEncoding.EncodeToString(vh[:])
		}

		lastUp := "Never"
		if fur.MapSize > 0 {
			lastUp = strconv.Itoa(int(fur.MapSize))
		}

		table.Append([]string{
			fur.email,
			valS,
			seq,
			lastUp,
		})
	}

	table.Render()
	return nil
}

// Utility method for getting all followed user records
func getAllFollowedUsers(db *bolt.DB) ([]*FollowedUserRecord, error) {
	rv := make([]*FollowedUserRecord, 0)
	err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("keys")).ForEach(func(k, v []byte) error {
			var fur FollowedUserRecord
			err := gob.NewDecoder(bytes.NewReader(v)).Decode(&fur)
			if err != nil {
				return err
			}
			fur.email = string(k)
			rv = append(rv, &fur)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return rv, nil
}
