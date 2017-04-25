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
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/json"
	"time"

	"github.com/continusec/objecthash"
)

// TokenData is used to form a basic structure that we take the object hash of before signing.
type tokenData struct {
	// Email is the email address this token is valid for
	Email string `json:"email"`

	// TTL is the time (seconds since epoch UTC) until this token is valid. Normally 1 hour after issue.
	TTL int64 `json:"ttl"`
}

// A token is a base64 of asn1 form of this.
type signedToken struct {
	// Signature for the TokenData
	Signature ECDSASignature

	// TTL is the time when this token expires. Email is not sent with the token, since
	// it is presented along with the set request.
	TTL int64
}

// Returns nil if valid - token should be base64 decoded already.
func validateToken(pkey *ecdsa.PublicKey, email string, token []byte) error {
	var sig signedToken
	_, err := asn1.Unmarshal(token, &sig)
	if err != nil {
		return err
	}

	if time.Now().After(time.Unix(sig.TTL, 0)) {
		return errTTLExpired
	}

	td := &tokenData{
		Email: email,
		TTL:   sig.TTL,
	}

	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(td)
	if err != nil {
		return err
	}

	jsonB := b.Bytes()
	oh, err := objecthash.CommonJSONHash(jsonB)
	if err != nil {
		return err
	}

	if !ecdsa.Verify(pkey, oh, sig.Signature.R, sig.Signature.S) {
		return errInvalidSig
	}

	return nil
}

// Creates a new token for the email address and specified TTL.
// Result is to be base64 encoded by caller.
func makeToken(pkey *ecdsa.PrivateKey, email string, ttl time.Time) ([]byte, error) {
	token := &tokenData{
		Email: email,
		TTL:   ttl.Unix(),
	}

	b := &bytes.Buffer{}
	err := json.NewEncoder(b).Encode(token)
	if err != nil {
		return nil, err
	}

	jsonB := b.Bytes()
	oh, err := objecthash.CommonJSONHash(jsonB)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, pkey, oh)
	if err != nil {
		return nil, err
	}

	sig, err := asn1.Marshal(signedToken{Signature: ECDSASignature{R: r, S: s}, TTL: token.TTL})
	if err != nil {
		return nil, err
	}

	return sig, nil
}
