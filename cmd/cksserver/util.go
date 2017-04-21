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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/continusec/verifiabledatastructures"

	"golang.org/x/net/context"
)

// PublicKeyData is the data stored for a map key in the Verifiable Map
type PublicKeyData struct {
	// Sequence number, starting from 0, of different values for this map key.
	// Our server guarantees we will always present sequentially increasing numbers for
	// any given map key, with no gaps or duplicates, beginning at 0.
	Sequence int64 `json:"sequence"`

	// PriorTreeSize is any prior tree size that had the value for this map key for Sequence - 1.
	// This is useful for a follow-up call to request the previous value for this map key.
	PriorTreeSize int64 `json:"priorTreeSize"`

	// The plain text email address for which this map key is valid
	Email string `json:"email"`

	// The public key data held for this key. It is simply stored as uploaded by the user
	// without any further validation.
	PGPPublicKey []byte `json:"pgpPublicKey"`
}

// GetEntryResult is the data returned when looking up data for an email address
type GetEntryResult struct {
	// VUFResult is the result of applying the VUF to the email address. This is
	// the PKCS15 signature of the SHA256 hash of the email address. This must be verified by
	// the client.
	VUFResult []byte `json:"vufResult"`

	// AuditPath is the set of Merkle Tree nodes that should be applied along with this
	// value to produce the Merkle Tree root hash for the Verifiable Map at this tree size.
	AuditPath [][]byte `json:"auditPath"`

	// TreeSize is the size of the Merkle Tree for which this inclusion proof is valid.
	TreeSize int64 `json:"treeSize"`

	// PublicKeyValue is a redacted JSON for PublicKeyData field.
	PublicKeyValue []byte `json:"publicKeyValue"`
}

// AddEntryResult is the data returned when setting a key in the map
type AddEntryResult struct {
	// MutationEntryLeafHash is the leaf hash of the entry added to the mutation log for the map.
	// Once this has been verified to be added to the mutation log for the map, then this entry
	// will be reflected for the map at that size (provided no conflicting operation occurred).
	MutationEntryLeafHash []byte `json:"mutationEntryLeafHash"`
}

// A token is a base64 of asn1 form of this.
type ECDSASignature struct {
	// R, S are as returned by ecdsa.Sign
	R, S *big.Int
}

// EmptyLeafHash is the leaf hash of an empty node, pre-calculated since used often.
var EmptyLeafHash = sha256.Sum256([]byte{0})

var (
	// The signature failed to validate - likely wrong email.
	ErrInvalidSig = errors.New("ErrInvalidSig")

	// The signature is too old
	ErrTTLExpired = errors.New("ErrTTLExpired")

	// We are unable to parse a given private key file
	ErrInvalidKey = errors.New("ErrInvalidKey")
)

// handleError logs an error and sets an appropriate HTTP status code.
func handleError(err error, r *http.Request, w http.ResponseWriter) {
	switch err { // TODO: handle better
	default:
		logError(getContext(r), fmt.Sprintf("Error: %v", err))
		w.WriteHeader(500)
	}
}

// Sign data using a private key and return an ASN1 serialized signature.
func ecSign(data []byte, key *ecdsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, hashed[:])
	if err != nil {
		return nil, err
	}
	sig, err := asn1.Marshal(ECDSASignature{R: r, S: s})
	if err != nil {
		return nil, err
	}
	return sig, nil
}

type responseGrabber struct {
	Contents *bytes.Buffer
	hdr      http.Header
	Status   int
}

func (rg *responseGrabber) Header() http.Header {
	if rg.hdr == nil {
		rg.hdr = make(http.Header)
	}
	return rg.hdr
}

func (rg *responseGrabber) Write(b []byte) (int, error) {
	if rg.Contents == nil {
		rg.Contents = &bytes.Buffer{}
	}
	return rg.Contents.Write(b)
}

func (rg *responseGrabber) WriteHeader(s int) {
	rg.Status = s
}

type signingWrapper struct {
	H http.Handler
}

func (wr *signingWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	respWrapper := &responseGrabber{}
	wr.H.ServeHTTP(respWrapper, r)
	var b []byte
	if respWrapper.Contents != nil {
		b = respWrapper.Contents.Bytes()
	}
	sig, err := ecSign(b, serverPrivateKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	for k, v := range respWrapper.Header() {
		w.Header()[k] = v
	}
	w.Header().Set("X-Body-Signature", base64.StdEncoding.EncodeToString(sig))
	if respWrapper.Status == 0 {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(respWrapper.Status)
	}
	w.Write(b)
}

// Write this data to an HttpResponse and then add a signature header.
func signItHandler(h http.Handler) http.Handler {
	return &signingWrapper{H: h}
}

// Returns a VerifiableMap object ready for manipulation using the mutating secret
// key.
func getMapObject(ctx context.Context) *verifiabledatastructures.VerifiableMap {
	return mapService.Account("0", "mutating").VerifiableMap("keys")
}

// Take the result of the VUF and convert this to a Verifiable Map key.
// We hash this primarily so that the mutation log (which auditors needs)
// won't be vulnerable to an offline directly harvest attack where an attacker
// can simply try to verify a list of VUF results against a generated list of email
// addresses.
func GetKeyForVUF(data []byte) []byte {
	rv := sha256.Sum256(data)
	return rv[:]
}

// Calculated the VUF to a plain text map key (email address) to produce a VUF result.
// Here that means make a PKCS15 signature over the input data.
func ApplyVUF(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, vufPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}
