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
	"strconv"

	"github.com/boltdb/bolt"
	"github.com/urfave/cli"
)

// Update the current state that we are tracking to either head (default)
// or a specific map size (> 0). Requesting size 0 is the equivalent of head.
func updateTree(db *bolt.DB, c *cli.Context) error {
	seq := 0
	switch c.NArg() {
	case 0:
		seq = 0
	case 1:
		var err error
		seq, err = strconv.Atoi(c.Args().Get(0))
		if err != nil {
			return err
		}
	default:
		return cli.NewExitError("wrong number of arguments specified", 1)
	}

	mapState, err := getCurrentHead("head")
	if err != nil {
		return err
	}

	vmap, err := getMap()
	if err != nil {
		return err
	}

	newMapState, err := vmap.VerifiedMapState(mapState, int64(seq))
	if err != nil {
		return err
	}

	if newMapState != nil {
		// check for any pending updates
		err = checkUpdateListForNewness(db, newMapState)
		if err != nil {
			return err
		}

		// update any keys we watch
		err = updateKeysToMapState(db, newMapState)
		if err != nil {
			return err
		}

		err = setCurrentHead("head", newMapState)
		if err != nil {
			return err
		}
	}

	return showStatus(db, c)
}
