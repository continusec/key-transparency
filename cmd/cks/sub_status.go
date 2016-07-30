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
	"errors"
	"fmt"

	"github.com/boltdb/bolt"
	"github.com/urfave/cli"
)

// Won't arg check, so can be called from other commands
func actuallyShowStatus(db *bolt.DB) error {
	mapState, err := getCurrentHead("head")
	if err != nil {
		return err
	}

	if mapState == nil {
		fmt.Printf("Empty map.\n")
	} else {
		fmt.Printf("Tracking revision: %d\n", mapState.TreeSize())
	}

	return nil
}

// Show the current status, ie head
func showStatus(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 0 {
		return errors.New("unexpected arguments")
	}

    return actuallyShowStatus(db)
}
