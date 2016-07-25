package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

// AddEntryResult is the data returned when setting a key in the map
type AddEntryResult struct {
	// MutationEntryLeafHash is the leaf hash of the entry added to the mutation log for the map.
	// Once this has been verified to be added to the mutation log for the map, then this entry
	// will be reflected for the map at that size (provided no conflicting operation occurred).
	MutationEntryLeafHash []byte `json:"mutationEntryLeafHash"`
}

type UpdateResult struct {
	// Email address that this was added for
	Email string

	// Mutation log entry as returned by the server
	MutationLeafHash []byte

	// sha256 of the value set
	ValueHash []byte

	// -1 means unknown
	LeafIndex int64

	// Timestamp when written
	Timestamp time.Time
}

func listUpdates(db *bolt.DB, c *cli.Context) error {
	var emailAddress string

	switch c.NArg() {
	case 0:
		// ignore
	case 1:
		emailAddress = c.Args().Get(0)
	default:
		return cli.NewExitError("incorrect number of arguments. see help", 1)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Email", "Value Hash", "Timestamp", "Mutation Log Entry", "Sequence"})

	ms, err := getCurrentHead("head")
	if err != nil {
		return err
	}

	gotOne := func(b *bolt.Bucket, k, v []byte) error {
		var ur UpdateResult
		err := gob.NewDecoder(bytes.NewReader(v)).Decode(&ur)
		if err != nil {
			return err
		}

		if ur.LeafIndex == -1 && c.Bool("check") && ms != nil {
			vmap, err := getMap()
			if err != nil {
				return err
			}
			proof, err := vmap.MutationLog().InclusionProof(ms.TreeSize(), &continusec.AddEntryResponse{EntryLeafHash: ur.MutationLeafHash})
			if err != nil {
				// pass, don't return err as it may not have been sequenced yet
			} else {
				err = proof.Verify(&ms.MapTreeHead.MutationLogTreeHead)
				if err != nil {
					return err
				}

				ur.LeafIndex = proof.LeafIndex

				buffer := &bytes.Buffer{}
				err = gob.NewEncoder(buffer).Encode(ur)
				if err != nil {
					return err
				}

				err = b.Put(k, buffer.Bytes())

				if err != nil {
					return err
				}
			}
		}

		table.Append([]string{
			ur.Email,
			base64.StdEncoding.EncodeToString(ur.ValueHash),
			ur.Timestamp.String()[:19],
			base64.StdEncoding.EncodeToString(ur.MutationLeafHash),
			strconv.Itoa(int(ur.LeafIndex)),
		})

		return nil
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("updates"))
		if len(emailAddress) == 0 {
			b.ForEach(func(k, v []byte) error { return gotOne(b, k, v) })
		} else {
			eh := sha256.Sum256([]byte(emailAddress))
			c := b.Cursor()
			k, v := c.Seek(eh[:])
			for k != nil {
				if !bytes.Equal(eh[:], k[:len(eh)]) {
					return nil
				}
				err := gotOne(b, k, v)
				if err != nil {
					return err
				}
				k, v = c.Next()
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	table.Render()

	return nil
}

func setKey(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 3 {
		return cli.NewExitError("incorrect number of arguments. see help", 1)
	}
	emailAddress := c.Args().Get(0)
	publicKeyPath := c.Args().Get(1)
	token := c.Args().Get(2)

	if strings.Index(emailAddress, "@") == -1 {
		return cli.NewExitError("email address not recognized", 4)
	}

	var pubKeyBytes []byte
	if publicKeyPath == "-" {
		var err error
		fmt.Println("Starting read...")
		pubKeyBytes, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		fmt.Println("Read complete.")
	} else {
		var err error
		pubKeyBytes, err = ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Setting key for %s with token...\n", emailAddress)

	var server string
	err := db.View(func(tx *bolt.Tx) error {
		server = string(tx.Bucket([]byte("conf")).Get([]byte("server")))
		return nil
	})
	if err != nil {
		return err
	}

	url := server + "/v1/publicKey/" + emailAddress

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(pubKeyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return err
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var aer AddEntryResult
	err = json.Unmarshal(contents, &aer)
	if err != nil {
		return err
	}

	fmt.Printf("Success. Leaf hash of mutation: %s\n", base64.StdEncoding.EncodeToString(aer.MutationEntryLeafHash))

	k1 := sha256.Sum256([]byte(emailAddress))

	// second part of key is a timestamp for sorting, does not need to match
	// any timestamp inside of the value
	k2 := make([]byte, 8)
	binary.BigEndian.PutUint64(k2, uint64(time.Now().UnixNano()))

	key := append(k1[:], k2...)

	buffer := &bytes.Buffer{}
	vh := sha256.Sum256(pubKeyBytes)
	err = gob.NewEncoder(buffer).Encode(&UpdateResult{
		Email:            emailAddress,
		MutationLeafHash: aer.MutationEntryLeafHash,
		ValueHash:        vh[:],
		LeafIndex:        -1,
		Timestamp:        time.Now(),
	})
	if err != nil {
		return err
	}

	value := buffer.Bytes()

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("updates"))
		err := b.Put(key, value)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func mailToken(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 1 {
		return cli.NewExitError("exactly one email address must be specified", 1)
	}
	emailAddress := c.Args().Get(0)

	if strings.Index(emailAddress, "@") == -1 {
		return cli.NewExitError("email address not recognized", 4)
	}

	if c.Bool("yes") || confirmIt(fmt.Sprintf("Are you sure you want to generate and send a token to address (%s)? Please only do so if you own that email account.", emailAddress)) {
		fmt.Printf("Sending mail to %s with token...\n", emailAddress)

		var server string
		err := db.View(func(tx *bolt.Tx) error {
			server = string(tx.Bucket([]byte("conf")).Get([]byte("server")))
			return nil
		})
		if err != nil {
			return handleError(err)
		}

		resp, err := http.Post(server+"/v1/sendToken/"+emailAddress, "", nil)
		if err != nil {
			return err
		}

		if resp.StatusCode != 200 {
			return cli.NewExitError("non-200 response received", resp.StatusCode)
		}

		fmt.Printf("Success. See email for further instructions.\n")
	} else {
		fmt.Printf("Cancelled.\n")
	}
	return nil
}
