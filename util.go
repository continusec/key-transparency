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

package keytransparency

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"strings"

	"golang.org/x/crypto/openpgp/armor"
)

// ECDSASignature marshalled as ASN.1 is the signature
type ECDSASignature struct {
	// R, S are as returned by ecdsa.Sign
	R, S *big.Int
}

// EmptyLeafHash is the leaf hash of an empty node, pre-calculated since used often.
var emptyLeafHash = sha256.Sum256([]byte{0})

var (
	// The signature failed to validate - likely wrong email.
	errInvalidSig = errors.New("ErrInvalidSig")

	// The signature is too old
	errTTLExpired = errors.New("ErrTTLExpired")
)

// Take the result of the VUF and convert this to a Verifiable Map key.
// We hash this primarily so that the mutation log (which auditors needs)
// won't be vulnerable to an offline directly harvest attack where an attacker
// can simply try to verify a list of VUF results against a generated list of email
// addresses.
func getKeyForVUF(data []byte) []byte {
	rv := sha256.Sum256(data)
	return rv[:]
}

// Calculated the VUF to a plain text map key (email address) to produce a VUF result.
// Here that means make a PKCS15 signature over the input data.
func applyVUF(pkey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, pkey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
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

// MustCreateRSAKeyFromPEM converts a string that should be a PEM of type "PRIVATE KEY" to an
// actual RSA private key.
func MustCreateRSAKeyFromPEM(s string) *rsa.PrivateKey {
	var p *pem.Block
	p, _ = pem.Decode([]byte(s))
	if p == nil {
		log.Fatal("no key found")
	}

	if !strings.HasSuffix(p.Type, "PRIVATE KEY") {
		log.Fatal("not private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	rv, ok := key.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("cannot cast")
	}

	return rv
}

// MustCreateECKeyFromPEM converts a string that should be a PEM of type "EC PRIVATE KEY" to an
// actual RSA private key.
func MustCreateECKeyFromPEM(s string) *ecdsa.PrivateKey {
	var p *pem.Block
	p, _ = pem.Decode([]byte(s))
	if p == nil {
		log.Fatal("no key found")
	}

	if !strings.HasSuffix(p.Type, "EC PRIVATE KEY") {
		log.Fatal("not private key")
	}

	key, err := x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return key
}
