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
	"errors"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/urfave/cli"
)

// Dump out the current public key data for 1 or more users. If none specified, all
// followed are exported. Should not result in any calls to the server provided all
// users were followed at last `cks update`
func exportUser(db *bolt.DB, c *cli.Context) error {
	todo := make([]string, 0)
	if c.NArg() == 0 {
		users, err := getAllFollowedUsers(db)
		if err != nil {
			return err
		}
		for _, fur := range users {
			todo = append(todo, fur.email)
		}
	} else {
		todo = append(todo, c.Args()...)
	}
	for _, emailAddress := range todo {
		if strings.Index(emailAddress, "@") == -1 {
			return errors.New("email address not recognized, no at-mark")
		}

		desiredSequence := int64(math.MaxInt64)
		spl := strings.Split(emailAddress, "/")
		haveSeq := false
		switch len(spl) {
		case 1:
			// pass, all good
		case 2:
			x, err := strconv.Atoi(spl[1])
			if err != nil {
				return err
			}
			desiredSequence = int64(x)
			emailAddress = spl[0]
			haveSeq = true
		default:
			return errors.New("email address not recognized, too many /es")
		}

		mapState, err := getCurrentHead("head")
		if err != nil {
			return err
		}

		// Zero size tree
		if mapState != nil {
			furs, err := getHistoryForUser(emailAddress, desiredSequence, mapState)
			if err != nil {
				return err
			}

			if len(furs) > 0 {
				if haveSeq {
					if furs[len(furs)-1].KeyData.Sequence != desiredSequence {
						return errors.New("unable to find record for users with desired sequence number")
					}
				}
				os.Stdout.Write(furs[len(furs)-1].KeyData.PGPPublicKey)
			}
		}
	}
	return nil
}
