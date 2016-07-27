package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/olekukonko/tablewriter"
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

// PublicKeyData is the data stored for a key in the Merkle Tree.
type PublicKeyData struct {
	// Sequence number, starting from 0, of different values for this key
	Sequence int64 `json:"sequence"`

	// PriorTreeSize is any prior tree size that had the value this key for Sequence - 1.
	PriorTreeSize int64 `json:"priorTreeSize"`

	// The plain text email address for which this key is valid
	Email string `json:"email"`

	// The public key data held for this key.
	PGPPublicKey []byte `json:"pgpPublicKey"`
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

func updateKeyToMapState(key string, ms *continusec.MapTreeState) error {
	res, err := getValForEmail(key, ms.TreeSize())
	if err != nil {
		return err
	}

	err = res.VerifyInclusion(ms)
	if err != nil {
		return err
	}

	err = validateVufResult(key, res.VUFResult)
	if err != nil {
		return err
	}

	if len(res.PublicKeyValue) > 0 {
		pkv := &continusec.RedactedJsonEntry{RedactedJsonBytes: res.PublicKeyValue}
		data, err := pkv.Data()
		if err != nil {
			return err
		}

		var pkd PublicKeyData
		err = json.NewDecoder(bytes.NewReader(data)).Decode(&pkd)
		if err != nil {
			return err
		}

		// this should always be true, but including to prevent loops
		if pkd.PriorTreeSize > 0 && pkd.PriorTreeSize < ms.TreeSize() {
			vmap, err := getMap()
			if err != nil {
				return err
			}
			nextMapState, err := vmap.VerifiedMapState(ms, pkd.PriorTreeSize)
			if err != nil {
				return err
			}
			err = updateKeyToMapState(key, nextMapState)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func updateKeysToMapState(db *bolt.DB, ms *continusec.MapTreeState) error {
	kvs := make([][2][]byte, 0)
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keys"))
		err := b.ForEach(func(k, v []byte) error {
			kvs = append(kvs, [2][]byte{k, v})
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, kv := range kvs {
		k := kv[0]
		email := string(k)

		err = updateKeyToMapState(email, ms)
		if err != nil {
			return err
		}
	}
	return nil
}

func listUsers(db *bolt.DB, c *cli.Context) error {
	kvs := make([][2][]byte, 0)
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keys"))
		err := b.ForEach(func(k, v []byte) error {
			kvs = append(kvs, [2][]byte{k, v})
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Email", "Last updated size"})

	for _, kv := range kvs {
		k, v := kv[0], kv[1]

		lastSeq := int64(binary.BigEndian.Uint64(v))
		email := string(k)

		table.Append([]string{
			email,
			strconv.Itoa(int(lastSeq)),
		})
	}

	table.Render()

	return nil

}

func followUser(db *bolt.DB, c *cli.Context) error {
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
		return err
	}
	return nil
}

func unfollowUser(db *bolt.DB, c *cli.Context) error {
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
		return err
	}

	return nil
}

var (
	ErrUnexpectedKeyFormat = errors.New("ErrUnexpectedKeyFormat")
)

func validateVufResult(email string, vufResult []byte) error {
	db, err := GetDB()
	if err != nil {
		return err
	}

	var vuf []byte
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("conf"))
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
	return rsa.VerifyPKCS1v15(ppkey, crypto.SHA256, hashed[:], vufResult)
}

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
		return cli.NewExitError("wrong number of argument specified", 1)
	}

	mapState, err := getCurrentHead("head")
	if err != nil {
		return handleError(err)
	}

	vmap, err := getMap()
	if err != nil {
		return err
	}

	newMapState, err := vmap.VerifiedMapState(mapState, int64(seq))
	if err != nil {
		return err
	}

	err = setCurrentHead("head", newMapState)
	if err != nil {
		return err
	}

	/*	err = updateKeysToMapState(db, newMapState)
		if err != nil {
			return err
		}*/

	fmt.Printf("Tree size set to: %d\n", newMapState.TreeSize())

	return nil
}

func setCurrentHead(key string, newMapState *continusec.MapTreeState) error {
	db, err := GetDB()
	if err != nil {
		return err
	}

	b := &bytes.Buffer{}
	err = gob.NewEncoder(b).Encode(newMapState)
	if err != nil {
		return err
	}

	return db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("conf")).Put([]byte(key), b.Bytes())
	})
}

func getCurrentHead(key string) (*continusec.MapTreeState, error) {
	var mapState continusec.MapTreeState

	db, err := GetDB()
	if err != nil {
		return nil, err
	}

	err = db.View(func(tx *bolt.Tx) error {
		return gob.NewDecoder(bytes.NewReader(tx.Bucket([]byte("conf")).Get([]byte(key)))).Decode(&mapState)
	})
	if err != nil {
		return nil, err
	}

	return &mapState, nil
}

var (
	ErrBadReturnVal = errors.New("ErrBadReturnVal")
)

func getValForEmail(emailAddress string, treeSize int64) (*GetEntryResult, error) {
	server, err := getServer()
	if err != nil {
		return nil, err
	}

	url := server + "/v1/publicKey/" + emailAddress + "/at/" + strconv.Itoa(int(treeSize))

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
