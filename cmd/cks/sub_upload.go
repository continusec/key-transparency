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
	"strings"
	"time"

	"golang.org/x/crypto/openpgp/armor"

	"github.com/boltdb/bolt"
	"github.com/urfave/cli"
)

// Upload a key to the server. Key should be armored PGP PUBLIC KEY and less than 1MB
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

	url := server + "/v2/publicKey/" + emailAddress

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
		return errors.New("Key already set to this value - no mutation generated")
	default:
		return errors.New(fmt.Sprintf("Unexpected server response: %d", resp.StatusCode))
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
		return tx.Bucket([]byte("updates")).Put(key, value)
	})
	if err != nil {
		return err
	}
	return nil
}

// Return nil if this is OK to be a value.
// We want there to be at least 1 valid PEM PGP PUBLIC KEY BLOCK,
// and if found, we will just store what we sent to us,
// provided it is less than 1 MB.
func validateData(data []byte) error {
	if len(data) > (1024 * 1024) {
		return errors.New("Data too large - currently 1MB limit")
	}

	p, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}

	if p == nil {
		return errors.New("Unable to parse as PGP PUBLIC KEY (armored)")
	}

	if p.Type != "PGP PUBLIC KEY BLOCK" {
		return errors.New("Unable to find PGP PUBLIC KEY BLOCK")
	}

	// All good
	return nil
}
