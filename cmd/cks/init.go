package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"os"
	"sort"

	"github.com/boltdb/bolt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

// Show text as-is if ASCII, else base64 with spacing.
func makePretty(data []byte) string {
	binary := false
	for _, b := range data {
		if b > 127 || (b < 31 && b != 9 && b != 10 && b != 13) {
			binary = true
			break
		}
	}
	if binary {
		s := base64.StdEncoding.EncodeToString(data)
		rv := ""
		for i := 0; i < len(s); i += 72 {
			j := i + 72
			if j > len(s) {
				j = len(s)
			}
			rv += s[i:j] + "\n"
		}
		return rv
	} else {
		return string(data)
	}
}

func showConf(db *bolt.DB, c *cli.Context) error {
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

type ByTimestamp []*CacheEntry

func (a ByTimestamp) Len() int           { return len(a) }
func (a ByTimestamp) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByTimestamp) Less(i, j int) bool { return a[i].Timestamp.Before(a[j].Timestamp) }

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

func initNewServer(c *cli.Context) error {
	if c.NArg() != 0 {
		return cli.NewExitError("No args should be specified", 1)
	}

	server := c.String("server")
	if c.Bool("yes") || confirmIt("Initialize new database with server: "+server+"? (this will overwrite any existing database)") {
		db, err := InitDB(server)
		if err != nil {
			return handleError(err)
		}
		defer db.Close()

		// First, get public key
		pubKey, err := doGet(server + "/v1/config/serverPublicKey")
		if err != nil {
			return handleError(err)
		}

		err = db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("conf")).Put([]byte("serverKey"), pubKey)
		})
		if err != nil {
			return handleError(err)
		}

		// Next, get VUF
		vufKey, err := doGet(server + "/v1/config/vufPublicKey")
		if err != nil {
			return handleError(err)
		}

		err = db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("conf")).Put([]byte("vufKey"), vufKey)
		})
		if err != nil {
			return handleError(err)
		}

		vmap, err := getMap()
		if err != nil {
			return handleError(err)
		}

		initialMapState, err := vmap.VerifiedLatestMapState(nil)
		if err != nil {
			return handleError(err)
		}

		b := &bytes.Buffer{}

		// nil is OK, it means the map has no entries
		if initialMapState != nil {
			err = gob.NewEncoder(b).Encode(initialMapState)
			if err != nil {
				return handleError(err)
			}
			err = db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("conf")).Put([]byte("head"), b.Bytes())
			})
			if err != nil {
				return handleError(err)
			}
		} else {
			err = db.Update(func(tx *bolt.Tx) error {
				return tx.Bucket([]byte("conf")).Put([]byte("nilheadok"), []byte{1})
			})
			if err != nil {
				return handleError(err)
			}
		}

		fmt.Println("Initialization complete.")
	} else {
		fmt.Println("Initialization cancelled.")
	}

	return nil
}
