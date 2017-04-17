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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

// Display history for a specific user - we don't have to be following them
func historyForUser(db *bolt.DB, c *cli.Context) error {
	if c.NArg() == 0 {
		return errors.New("at least one email address must be specified")
	}
	for _, emailAddress := range c.Args() {
		if strings.Index(emailAddress, "@") == -1 {
			return errors.New("email address not recognized")
		}

		mapState, err := getCurrentHead("head")
		if err != nil {
			return err
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Email", "Value Hash", "User Sequence", "Map Size Retrieved At"})

		// Zero size tree
		if mapState != nil {
			furs, err := getHistoryForUser(emailAddress, -1, mapState)
			if err != nil {
				return err
			}

			for _, fur := range furs {
				vh := sha256.Sum256(fur.KeyData.PGPPublicKey)
				table.Append([]string{
					emailAddress,
					base64.StdEncoding.EncodeToString(vh[:]),
					strconv.Itoa(int(fur.KeyData.Sequence)),
					strconv.Itoa(int(fur.MapSize)),
				})
			}
		}

		table.Render()
	}
	return nil
}
