package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

var (
	ErrWrongSequence = errors.New("ErrWrongSequence")
)

type FollowedUserRecord struct {
	MapSize int64
	KeyData *PublicKeyData
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

func getVerifiedValueForMapState(key string, ms *continusec.MapTreeState) (*PublicKeyData, error) {
	res, err := getValForEmail(key, ms.TreeSize())
	if err != nil {
		return nil, err
	}

	err = res.VerifyInclusion(ms)
	if err != nil {
		return nil, err
	}

	err = validateVufResult(key, res.VUFResult)
	if err != nil {
		return nil, err
	}

	if len(res.PublicKeyValue) == 0 { // it's ok to get an empty result
		return nil, nil
	} else {
		pkv := &continusec.RedactedJsonEntry{RedactedJsonBytes: res.PublicKeyValue}
		data, err := pkv.Data()
		if err != nil {
			return nil, err
		}

		var pkd PublicKeyData
		err = json.NewDecoder(bytes.NewReader(data)).Decode(&pkd)
		if err != nil {
			return nil, err
		}

		if pkd.Email != key {
			return nil, ErrUnexpectedEmail
		}

		return &pkd, nil
	}
}

func updateKeyToMapState(db *bolt.DB, emailAddress string, ms *continusec.MapTreeState) error {
	pkd, err := getVerifiedValueForMapState(emailAddress, ms)
	if err != nil {
		return err
	}
	buffer := &bytes.Buffer{}
	err = gob.NewEncoder(buffer).Encode(&FollowedUserRecord{
		MapSize: ms.TreeSize(),
		KeyData: pkd,
	})
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("keys")).Put([]byte(emailAddress), buffer.Bytes())
	})
}

func updateKeysToMapState(db *bolt.DB, ms *continusec.MapTreeState) error {
	kvs := make([]string, 0)
	err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("keys")).ForEach(func(k, v []byte) error {
			kvs = append(kvs, string(k))
			return nil
		})
	})
	if err != nil {
		return err
	}
	for _, email := range kvs {
		err = updateKeyToMapState(db, email, ms)
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
			kvs = append(kvs, [2][]byte{copySlice(k), copySlice(v)})
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
	table.SetHeader([]string{"Email", "Value Hash", "User Sequence", "Last Updated"})

	for _, kv := range kvs {
		k, v := kv[0], kv[1]

		email := string(k)
		var fur FollowedUserRecord
		err = gob.NewDecoder(bytes.NewReader(v)).Decode(&fur)
		if err != nil {
			return err
		}

		seq := "No key found"
		valS := "(none)"

		if fur.KeyData != nil {
			seq = strconv.Itoa(int(fur.KeyData.Sequence))
			vh := sha256.Sum256(fur.KeyData.PGPPublicKey)
			valS = base64.StdEncoding.EncodeToString(vh[:])
		}

		lastUp := "Never"
		if fur.MapSize > 0 {
			lastUp = strconv.Itoa(int(fur.MapSize))
		}

		table.Append([]string{
			email,
			valS,
			seq,
			lastUp,
		})
	}

	table.Render()

	return nil

}

func getHistoryForUser(emailAddress string, seqToStopAt int64, mapState *continusec.MapTreeState) ([]*FollowedUserRecord, error) {
	vmap, err := getMap()
	if err != nil {
		return nil, err
	}

	rv := make([]*FollowedUserRecord, 0)

	done := false
	expectedSeq := int64(-10)
	for !done {
		pkd, err := getVerifiedValueForMapState(emailAddress, mapState)
		if err != nil {
			return nil, err
		}
		if pkd == nil {
			if expectedSeq >= 0 {
				return nil, ErrWrongSequence
			}
			done = true
		} else {
			if expectedSeq != -10 {
				if pkd.Sequence != expectedSeq {
					return nil, ErrWrongSequence
				}
			}
			expectedSeq = pkd.Sequence - 1
			if expectedSeq < -1 {
				return nil, ErrWrongSequence
			}

			rv = append(rv, &FollowedUserRecord{
				KeyData: pkd,
				MapSize: mapState.TreeSize(),
			})

			if pkd.PriorTreeSize == 0 {
				done = true
			} else {
				if pkd.Sequence <= seqToStopAt {
					done = true
				} else {
					mapState, err = vmap.VerifiedMapState(mapState, pkd.PriorTreeSize)
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return rv, nil
}

func exportUser(db *bolt.DB, c *cli.Context) error {
	if c.NArg() == 0 {
		return cli.NewExitError("at least one email address must be specified", 1)
	}
	for _, emailAddress := range c.Args() {
		if strings.Index(emailAddress, "@") == -1 {
			return cli.NewExitError("email address not recognized", 4)
		}

		desiredSequence := int64(math.MaxInt64)
		spl := strings.Split(emailAddress, "/")
		haveSeq := false
		switch len(spl) {
		case 1:
			// pass, all good
		case 2:
			x, err := strconv.Atoi(spl[1])
			if err != nil {
				return err
			}
			desiredSequence = int64(x)
			emailAddress = spl[0]
			haveSeq = true
		default:
			return cli.NewExitError("email address not recognized", 5)
		}

		mapState, err := getCurrentHead("head")
		if err != nil {
			return err
		}

		// Zero size tree
		if mapState != nil {
			furs, err := getHistoryForUser(emailAddress, desiredSequence, mapState)
			if err != nil {
				return err
			}

			if len(furs) > 0 {
				if haveSeq {
					if furs[len(furs)-1].KeyData.Sequence != desiredSequence {
						return ErrWrongSequence
					}
				}
				os.Stdout.Write(furs[len(furs)-1].KeyData.PGPPublicKey)
			}
		}
	}
	return nil
}

func historyForUser(db *bolt.DB, c *cli.Context) error {
	if c.NArg() == 0 {
		return cli.NewExitError("at least one email address must be specified", 1)
	}
	for _, emailAddress := range c.Args() {
		if strings.Index(emailAddress, "@") == -1 {
			return cli.NewExitError("email address not recognized", 4)
		}

		mapState, err := getCurrentHead("head")
		if err != nil {
			return err
		}

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Email", "Value Hash", "User Sequence", "Map Size Retrieved At"})

		// Zero size tree
		if mapState != nil {
			furs, err := getHistoryForUser(emailAddress, -1, mapState)
			if err != nil {
				return err
			}

			for _, fur := range furs {
				vh := sha256.Sum256(fur.KeyData.PGPPublicKey)
				table.Append([]string{
					emailAddress,
					base64.StdEncoding.EncodeToString(vh[:]),
					strconv.Itoa(int(fur.KeyData.Sequence)),
					strconv.Itoa(int(fur.MapSize)),
				})
			}
		}

		table.Render()
	}
	return nil
}

func followUser(db *bolt.DB, c *cli.Context) error {
	if c.NArg() == 0 {
		return cli.NewExitError("at least one email address must be specified", 1)
	}
	for _, emailAddress := range c.Args() {
		if strings.Index(emailAddress, "@") == -1 {
			return cli.NewExitError("email address not recognized", 4)
		}

		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("keys"))
			k := []byte(emailAddress)
			v := b.Get(k)

			if len(v) == 0 {
				buffer := &bytes.Buffer{}

				err := gob.NewEncoder(buffer).Encode(&FollowedUserRecord{})
				if err != nil {
					return err
				}

				err = b.Put(k, buffer.Bytes())
				if err != nil {
					return err
				}
			}

			return nil
		})
		if err != nil {
			return err
		}
		fmt.Printf("Following %s.\n", emailAddress)
	}
	return nil
}

func unfollowUser(db *bolt.DB, c *cli.Context) error {
	if c.NArg() == 0 {
		return cli.NewExitError("at least one email address must be specified", 1)
	}
	for _, emailAddress := range c.Args() {
		if strings.Index(emailAddress, "@") == -1 {
			return cli.NewExitError("email address not recognized", 4)
		}

		err := db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("keys"))
			k := []byte(emailAddress)
			v := b.Get(k)
			if len(v) != 0 {
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
		fmt.Printf("No longer following %s.\n", emailAddress)
	}
	return nil
}

var (
	ErrUnexpectedKeyFormat = errors.New("ErrUnexpectedKeyFormat")
	ErrUnexpectedEmail     = errors.New("ErrUnexpectedEmail")
)

func validateVufResult(email string, vufResult []byte) error {
	db, err := GetDB()
	if err != nil {
		return err
	}

	var vuf []byte
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("conf"))
		vuf = copySlice(b.Get([]byte("vufKey")))
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
