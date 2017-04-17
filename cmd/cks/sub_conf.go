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
	"os"

	"github.com/boltdb/bolt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

// Display all values in the configuration database
func showConf(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 0 {
		return errors.New("unexpected arguments")
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Key", "Value (base-64)"})

	err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("conf")).ForEach(func(k, v []byte) error {
			table.Append([]string{
				string(k),
				makePretty(v),
			})
			return nil
		})
	})
	if err != nil {
		return err
	}

	table.Render()
	return nil
}
