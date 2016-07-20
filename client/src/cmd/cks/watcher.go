package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/urfave/cli"
)

// GetEntryResult is the data returned when looking up data for an email address
type GetEntryResult struct {
	// VUFResult is the result of applying the VUF to the email address. In practice this is
	// the PKCS15 signature of the SHA256 hash of the email address. This must be verified by
	// the client.
	VUFResult []byte `json:"vufResult"`

	// AuditPath is the set of Merkle Tree nodes that should be applied along with this
	// value to produce the Merkle Tree root hash.
	AuditPath [][]byte `json:"auditPath"`

	// TreeSize is the size of the Merkle Tree for which this inclusion proof is valid.
	TreeSize int64 `json:"treeSize"`

	// PublicKeyValue is a redacted JSON for PublicKeyData field.
	PublicKeyValue []byte `json:"publicKeyValue"`
}

// Verify that this result is included in the given map state
func (ger *GetEntryResult) VerifyInclusion(ms *continusec.MapTreeState) error {
	x := sha256.Sum256(ger.VUFResult)
	return (&continusec.MapInclusionProof{
		TreeSize:  ger.TreeSize,
		AuditPath: ger.AuditPath,
		Value:     &continusec.RedactedJsonEntry{RedactedJsonBytes: ger.PublicKeyValue},
		Key:       x[:],
	}).Verify(&ms.MapTreeHead)
}

func listUsers(c *cli.Context) error { /*
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Email", "Last updated size"})

		ms, err := getCurrentHead()
		if err != nil {
			return cli.NewExitError("error getting current map state from local storage: "+err.Error(), 1)
		}

		gotOne := func(b *bolt.Bucket, k, v []byte) error {
			lastSeq := int64(binary.BigEndian.Uint64(v))
			email := string(k)

			if ms != nil && lastSeq < ms.TreeSize() && c.Bool("check") {
				res, err := getValForEmail(email, ms.TreeSize(), c)
				if err != nil {
					return err
				}

				err = res.VerifyInclusion(ms)
				if err != nil {
					return err
				}

				err = validateVufResult(email, res.VUFResult)
				if err != nil {
					return err
				}

				lastSeq = res.TreeSize
			}

			table.Append([]string{
				email,
				strconv.Itoa(int(lastSeq)),
			})

			return nil
		}

		err = db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("keys"))
			err := b.ForEach(func(k, v []byte) error { return gotOne(b, k, v) })
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return cli.NewExitError("error writing result to local DB: "+err.Error(), 5)
		}

		table.Render()
	*/
	return nil

}

func followUser(c *cli.Context) error { /*
		if c.NArg() != 1 {
			return cli.NewExitError("exactly one email address must be specified", 1)
		}
		emailAddress := c.Args().Get(0)

		if strings.Index(emailAddress, "@") == -1 {
			return cli.NewExitError("email address not recognized", 4)
		}

		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("keys"))
			k := []byte(emailAddress)
			v := b.Get(k)
			if v == nil {
				k2 := make([]byte, 8)
				binary.BigEndian.PutUint64(k2, 0)
				err := b.Put(k, k2[:])
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return cli.NewExitError("error storing user to follow: "+err.Error(), 2)
		}
	*/
	return nil
}

func unfollowUser(c *cli.Context) error { /*
		if c.NArg() != 1 {
			return cli.NewExitError("exactly one email address must be specified", 1)
		}
		emailAddress := c.Args().Get(0)

		if strings.Index(emailAddress, "@") == -1 {
			return cli.NewExitError("email address not recognized", 4)
		}

		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("keys"))
			k := []byte(emailAddress)
			v := b.Get(k)
			if v != nil {
				err := b.Delete(k)
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return cli.NewExitError("error storing user to unfollow: "+err.Error(), 2)
		}
	*/
	return nil
}

var (
	ErrUnexpectedKeyFormat = errors.New("ErrUnexpectedKeyFormat")
)

func validateVufResult(email string, vufResult []byte) error { /*
		var vuf []byte
		err := db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("mapstate"))
			vuf = b.Get([]byte("vufKey"))
			return nil
		})
		if err != nil {
			return err
		}

		pkey, err := x509.ParsePKIXPublicKey(vuf)
		if err != nil {
			return err
		}

		ppkey, ok := pkey.(*rsa.PublicKey)
		if !ok {
			return ErrUnexpectedKeyFormat
		}

		hashed := sha256.Sum256([]byte(email))
		return rsa.VerifyPKCS1v15(ppkey, crypto.SHA256, hashed[:], vufResult)*/
	return nil
}

func updateTree(c *cli.Context) error {
	mapState, err := getCurrentHead()
	if err != nil {
		return handleError(err)
	}

	vmap, err := getMap()
	if err != nil {
		return handleError(err)
	}

	seq := c.Int("sequence")

	newMapState, err := vmap.VerifiedMapState(mapState, int64(seq))
	if err != nil {
		return handleError(err)
	}

	b := &bytes.Buffer{}
	err = gob.NewEncoder(b).Encode(newMapState)
	if err != nil {
		return handleError(err)
	}

	db, err := GetDB()
	if err != nil {
		return handleError(err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("mapstate")).Put([]byte("head"), b.Bytes())
	})
	if err != nil {
		return handleError(err)
	}

	fmt.Printf("Tree size set to: %d\n", newMapState.TreeSize())

	return nil
}

func getCurrentHead() (*continusec.MapTreeState, error) {
	var mapState continusec.MapTreeState

	db, err := GetDB()
	if err != nil {
		return nil, err
	}

	err = db.View(func(tx *bolt.Tx) error {
		return gob.NewDecoder(bytes.NewReader(tx.Bucket([]byte("mapstate")).Get([]byte("head")))).Decode(&mapState)
	})
	if err != nil {
		return nil, err
	}

	return &mapState, nil
}

var (
	ErrBadReturnVal = errors.New("ErrBadReturnVal")
)

func getValForEmail(emailAddress string, treeSize int64, c *cli.Context) (*GetEntryResult, error) {
	url := c.GlobalString("server") + "/v1/publicKey/" + emailAddress + "/at/" + strconv.Itoa(int(treeSize))

	fmt.Println(url)

	contents, err := doGet(url)
	if err != nil {
		return nil, err
	}

	var ger GetEntryResult
	err = json.Unmarshal(contents, &ger)
	if err != nil {
		return nil, err
	}

	return &ger, nil
}
