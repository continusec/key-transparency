package main

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"os"
	"strings"

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

func showConf(c *cli.Context) error {
	db, err := GetDB()
	if err != nil {
		return handleError(err)
	}
	defer db.Close()

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Key", "Value (base-64)"})

	err = db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("conf")).ForEach(func(k, v []byte) error {
			table.Append([]string{
				string(k),
				makePretty(v),
			})
			return nil
		})
	})
	if err != nil {
		return handleError(err)
	}

	table.Render()
	return nil
}

func showCache(c *cli.Context) error {
	db, err := GetDB()
	if err != nil {
		return handleError(err)
	}
	defer db.Close()

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"URL", "Timestamp", "Signature", "Data"})

	err = db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("cache")).ForEach(func(k, v []byte) error {
			var entry CacheEntry
			err := gob.NewDecoder(bytes.NewBuffer(v)).Decode(&entry)
			if err != nil {
				return err
			}
			table.Append([]string{
				string(k)[strings.Index(string(k), "/v1/"):],
				entry.Timestamp.String()[:19],
				makePretty(entry.Signature),
				makePretty(entry.Data),
			})
			return nil
		})
	})
	if err != nil {
		return handleError(err)
	}

	table.Render()

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
		fmt.Println("Fetching public key for server...")

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

		fmt.Println("Received, verified (signed by self) and stored.")

		// Next, get VUF
		fmt.Println("Fetching VUF key...")

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

		fmt.Println("Received, verified (signed by server key) and stored.")

		vmap, err := getMap()
		if err != nil {
			return handleError(err)
		}

		initialMapState, err := vmap.VerifiedLatestMapState(nil)
		if err != nil {
			return handleError(err)
		}

		b := &bytes.Buffer{}
		err = gob.NewEncoder(b).Encode(initialMapState)
		if err != nil {
			return handleError(err)
		}

		err = db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte("mapstate")).Put([]byte("head"), b.Bytes())
		})
		if err != nil {
			return handleError(err)
		}

		fmt.Println("Received initial map head state.")

		fmt.Println("Initialization complete.")
	} else {
		fmt.Println("Initialization cancelled.")
	}

	return nil
}
