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
	"fmt"
	"os"
	"sort"

	"github.com/boltdb/bolt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

type ByTimestamp []*CacheEntry

func (a ByTimestamp) Len() int           { return len(a) }
func (a ByTimestamp) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByTimestamp) Less(i, j int) bool { return a[i].Timestamp.Before(a[j].Timestamp) }

// Display values in cache - either as a table with no values, or individually if requested
func showCache(db *bolt.DB, c *cli.Context) error {
	switch c.NArg() {
	case 0:
		entries := make([]*CacheEntry, 0)
		err := db.View(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("cache")).ForEach(func(k, v []byte) error {
				var entry CacheEntry
				err := gob.NewDecoder(bytes.NewBuffer(v)).Decode(&entry)
				if err != nil {
					return err
				}
				entry.url = string(k)
				entries = append(entries, &entry)
				return nil
			})
		})
		if err != nil {
			return err
		}

		sort.Sort(ByTimestamp(entries))

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Timestamp", "URL"})
		for _, entry := range entries {
			table.Append([]string{
				entry.Timestamp.String()[:19],
				entry.url,
			})
		}
		table.Render()
	case 1:
		entry, err := (&CachingVerifyingRT{DB: db}).getValFromCache(c.Args().Get(0))
		if err != nil {
			return err
		}

		fmt.Printf("Data:\n%s\b\n\nSignature:\n%s\n", makePretty(entry.Data), makePretty(entry.Signature))
	default:
		return cli.NewExitError("Wrong number of arguments", 1)
	}

	return nil
}
