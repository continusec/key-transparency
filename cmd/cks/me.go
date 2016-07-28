package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp/armor"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

var (
	ErrUnexpectedResult = errors.New("ErrUnexpectedResult")
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

	// -1 means unknown. -2 means never took effect
	UserSequence int64

	// Timestamp when written
	Timestamp time.Time
}

func checkUpdateListForNewness(db *bolt.DB, ms *continusec.MapTreeState) error {
	results := make([][2][]byte, 0)
	gotOne := func(k, v []byte) error {
		results = append(results, [2][]byte{copySlice(k), copySlice(v)})
		return nil
	}
	err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("updates")).ForEach(func(k, v []byte) error { return gotOne(k, v) })
	})
	if err != nil {
		return err
	}
	for _, r := range results {
		k := r[0]
		v := r[1]

		var ur UpdateResult
		err := gob.NewDecoder(bytes.NewReader(v)).Decode(&ur)
		if err != nil {
			return err
		}

		if ur.LeafIndex == -1 {
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

				// Next, check if the value took effect - remember to add 1 to the leaf index, e.g. mutation 6 is tree size 7
				mapStateForMut, err := vmap.VerifiedMapState(ms, proof.LeafIndex+1)
				if err != nil {
					return err
				}

				// See what we can get in that map state
				pkd, err := getVerifiedValueForMapState(ur.Email, mapStateForMut)
				if err != nil {
					return err
				}

				// This ought not happen - we could have conflicted with another, but not empty.
				if pkd == nil {
					return ErrUnexpectedResult
				}

				// Now, see if we wrote the value we wanted
				vh := sha256.Sum256(pkd.PGPPublicKey)
				if bytes.Equal(vh[:], ur.ValueHash) {
					ur.UserSequence = pkd.Sequence
				} else {
					ur.UserSequence = -2
				}

				buffer := &bytes.Buffer{}
				err = gob.NewEncoder(buffer).Encode(ur)
				if err != nil {
					return err
				}

				err = db.Update(func(tx *bolt.Tx) error {
					return tx.Bucket([]byte("updates")).Put(k, buffer.Bytes())
				})

				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func listUpdates(db *bolt.DB, c *cli.Context) error {
	results := make([][2][]byte, 0)
	gotOne := func(k, v []byte) error {
		results = append(results, [2][]byte{copySlice(k), copySlice(v)})
		return nil
	}
	err := db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("updates")).ForEach(func(k, v []byte) error { return gotOne(k, v) })
	})
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Email", "Value Hash", "Timestamp", "Mutation Log Entry", "Map Sequence", "User Sequence"})

	for _, r := range results {
		v := r[1]

		var ur UpdateResult
		err := gob.NewDecoder(bytes.NewReader(v)).Decode(&ur)
		if err != nil {
			return err
		}

		var mutSeq, userSeq string

		switch ur.LeafIndex {
		case -1:
			mutSeq = "Not yet sequenced"
		default:
			mutSeq = strconv.Itoa(int(ur.LeafIndex))

			switch ur.UserSequence {
			case -1:
				userSeq = "Not yet sequenced"
			case -2:
				userSeq = "Conflict - not sequenced"
			default:
				userSeq = strconv.Itoa(int(ur.UserSequence))
			}
		}

		table.Append([]string{
			ur.Email,
			base64.StdEncoding.EncodeToString(ur.ValueHash),
			ur.Timestamp.String()[:19],
			base64.StdEncoding.EncodeToString(ur.MutationLeafHash),
			mutSeq,
			userSeq,
		})
	}

	table.Render()
	return nil
}

// Return nil if this is OK to be a value.
// We want there to be at least 1 valid PEM PGP PUBLIC KEY BLOCK,
// and if found, we will just store what we sent to us,
// provided it is less than 1 MB.
func validateData(data []byte) error {
	if len(data) > (1024 * 1024) {
		return ErrUnexpectedResult
	}

	p, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}

	if p == nil {
		return ErrUnexpectedResult
	}

	if p.Type != "PGP PUBLIC KEY BLOCK" {
		return ErrUnexpectedResult
	}

	// All good
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
		pubKeyBytes, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		var err error
		pubKeyBytes, err = ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return err
		}
	}

	err := validateData(pubKeyBytes)
	if err != nil {
		return cli.NewExitError("unrecognized data. check it is an armored PGP PUBLIC KEY, e.g. gpg --armor --export and less than 1MB", 4)
	}

	fmt.Printf("Setting key for %s with token...\n", emailAddress)

	server, err := getServer()
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

	switch resp.StatusCode {
	case 200:
		// continue
	case 204:
		fmt.Println("Key already set to this value - no mutation generated.")
		return nil
	default:
		return ErrUnexpectedResult
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
		UserSequence:     -1,
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

		server, err := getServer()
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
