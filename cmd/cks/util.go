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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/continusec/verifiabledatastructures"
	"github.com/urfave/cli"
)

// Return true if user types "yes"
func confirmIt(prompt string) bool {
	for {
		fmt.Printf("%s Type yes or no to continue: ", prompt)

		var resp string
		_, err := fmt.Scanln(&resp)
		if err == io.EOF {
			return false
		}

		resp = strings.ToLower(strings.TrimSpace(resp))
		switch {
		case strings.HasPrefix(resp, "yes"):
			return true
		case strings.HasPrefix(resp, "no"):
			return false
		}
	}
}

// Run a command, ensuring that it has a database, and will wrap any returned errors
// correctly
func stdCmd(f func(db *bolt.DB, c *cli.Context) error) func(c *cli.Context) error {
	return func(c *cli.Context) error {
		db, err := GetDB()
		if err != nil {
			return cli.NewExitError("Error: "+err.Error(), 1)
		}
		defer db.Close()

		err = f(db, c)
		if err != nil {
			return cli.NewExitError("Error: "+err.Error(), 1)
		}

		return nil
	}
}

// Copy byte slice - useful for bolt.DB calls where key, values slices are not valid
// once the transaction is closed.
func copySlice(a []byte) []byte {
	rv := make([]byte, len(a))
	copy(rv, a)
	return rv
}

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
	}
	return string(data)
}

// Verify data signed with ECDSA public key
func verifySignedData(data, sig, pub []byte) error {
	hashed := sha256.Sum256(data)

	var s ECDSASignature
	_, err := asn1.Unmarshal(sig, &s)
	if err != nil {
		return err
	}

	pkey, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return err
	}

	ppkey, ok := pkey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("Public key format for the server appears incorrect. Should be ecdsa.PublicKey but unable to cast as such.")
	}

	if !ecdsa.Verify(ppkey, hashed[:], s.R, s.S) {
		return errors.New("Verification of signed data failed.")
	}

	return nil
}

// Is this VUF result valid for this email address?
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
		return errors.New("Public key format for the VUF appears incorrect. Should be rsa.PublicKey but unable to cast as such.")
	}

	hashed := sha256.Sum256([]byte(email))
	return rsa.VerifyPKCS1v15(ppkey, crypto.SHA256, hashed[:], vufResult)
}

// Set current head value. key is usually "head"
func setCurrentHead(key string, newMapState *verifiabledatastructures.MapTreeState) error {
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
		err = tx.Bucket([]byte("conf")).Delete([]byte("nil" + key + "ok"))
		if err != nil {
			return err
		}
		return tx.Bucket([]byte("conf")).Put([]byte(key), b.Bytes())
	})
}

// Get current head value. key is usually "head"
func getCurrentHead(key string) (*verifiabledatastructures.MapTreeState, error) {
	var mapState verifiabledatastructures.MapTreeState
	var empty bool

	db, err := GetDB()
	if err != nil {
		return nil, err
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("conf")).Get([]byte(key))
		if len(b) == 0 {
			if bytes.Equal(tx.Bucket([]byte("conf")).Get([]byte("nil"+key+"ok")), []byte{1}) {
				empty = true
				return nil
			}
			return errors.New("Unable to find head in database")
		}
		return gob.NewDecoder(bytes.NewReader(b)).Decode(&mapState)
	})
	if err != nil {
		return nil, err
	}

	if empty {
		return nil, nil
	}
	return &mapState, nil
}
