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
	"encoding/gob"
	"errors"
	"fmt"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/urfave/cli"
)

// Add one or more users to the list of users that we are following
func followUser(db *bolt.DB, c *cli.Context) error {
	if c.NArg() == 0 {
		return errors.New("at least one email address must be specified")
	}
	for _, emailAddress := range c.Args() {
		if strings.Index(emailAddress, "@") == -1 {
			return errors.New("email address not recognized")
		}

		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("keys"))
			k := []byte(emailAddress)
			v := b.Get(k)

			if len(v) == 0 {
				buffer := &bytes.Buffer{}

				err := gob.NewEncoder(buffer).Encode(&FollowedUserRecord{})
				if err != nil {
					return err
				}

				err = b.Put(k, buffer.Bytes())
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return err
		}
		fmt.Printf("Following %s.\n", emailAddress)
	}
	return nil
}
