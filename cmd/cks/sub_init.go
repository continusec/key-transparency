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
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/boltdb/bolt"
	"github.com/urfave/cli"
)

// Called to wipe database and initialize new configuration
func initNewServer(c *cli.Context) error {
	if c.NArg() != 0 {
		return cli.NewExitError("No args should be specified", 1)
	}

	server := c.String("server")
	if c.Bool("yes") || confirmIt("Initialize new database with server: "+server+"? (this will overwrite any existing database)") {
		var err error
		ourDB, err = openDB(false, true)
		if err != nil {
			return cli.NewExitError("Error opening new database: "+err.Error(), 1)
		}
		defer ourDB.Close()

		// Start by creating empty buckets
		err = ourDB.Update(func(tx *bolt.Tx) error {
			conf, err := tx.CreateBucket([]byte("conf"))
			if err != nil {
				return err
			}

			err = conf.Put([]byte("server"), []byte(server))
			if err != nil {
				return err
			}

			_, err = tx.CreateBucket([]byte("mapstate"))
			if err != nil {
				return err
			}

			_, err = tx.CreateBucket([]byte("cache"))
			if err != nil {
				return err
			}

			_, err = tx.CreateBucket([]byte("updates"))
			if err != nil {
				return err
			}

			_, err = tx.CreateBucket([]byte("keys"))
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return cli.NewExitError("Error initializing database: "+err.Error(), 1)
		}

		// First, get public key
		pubKey, err := doGet(server + "/v2/config/serverPublicKey")
		if err != nil {
			return cli.NewExitError("Error initializing database with public key: "+err.Error(), 1)
		}

		err = ourDB.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("conf")).Put([]byte("serverKey"), pubKey)
		})
		if err != nil {
			return cli.NewExitError("Error initializing database with public key: "+err.Error(), 1)
		}

		// Next, get VUF
		vufKey, err := doGet(server + "/v2/config/vufPublicKey")
		if err != nil {
			return cli.NewExitError("Error initializing database with VUF key: "+err.Error(), 1)
		}

		err = ourDB.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("conf")).Put([]byte("vufKey"), vufKey)
		})
		if err != nil {
			return cli.NewExitError("Error initializing database with VUF key: "+err.Error(), 1)
		}

		vmap, err := getMap()
		if err != nil {
			return cli.NewExitError("Error initializing database: "+err.Error(), 1)
		}

		initialMapState, err := vmap.VerifiedLatestMapState(nil)
		if err != nil {
			return cli.NewExitError("Error initializing database with initial map state: "+err.Error(), 1)
		}

		b := &bytes.Buffer{}

		// nil is OK, it means the map has no entries
		if initialMapState != nil {
			err = gob.NewEncoder(b).Encode(initialMapState)
			if err != nil {
				return cli.NewExitError("Error initializing database with initial map state: "+err.Error(), 1)
			}
			err = ourDB.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("conf")).Put([]byte("head"), b.Bytes())
			})
			if err != nil {
				return cli.NewExitError("Error initializing database with initial map state: "+err.Error(), 1)
			}
		} else {
			err = ourDB.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("conf")).Put([]byte("nilheadok"), []byte{1})
			})
			if err != nil {
				return cli.NewExitError("Error initializing database with initial map state: "+err.Error(), 1)
			}
		}

		fmt.Println("Initialization complete.")
	} else {
		fmt.Println("Initialization cancelled.")
	}

	return nil
}

// Used by GetDB / InitDB below
var ourDB *bolt.DB

// Get the current database, returning error if unavailable, caching if there
func GetDB() (*bolt.DB, error) {
	if ourDB == nil {
		var err error
		ourDB, err = openDB(true, false)
		if err != nil {
			return nil, errors.New("Error opening database. If this is your first time running the tool, run `cks init` to initialize the local database.")
		}
	}
	return ourDB, nil
}

// Used by GetDB / init
func openDB(failIfNotThere, deleteExisting bool) (*bolt.DB, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join(u.HomeDir, ".cksdb")

	if failIfNotThere {
		_, err := os.Stat(dbPath)
		if err != nil { // probabably doesn't exist
			return nil, err
		}
	}

	if deleteExisting {
		err = os.Remove(dbPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		}
	}

	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}

	return db, nil
}
