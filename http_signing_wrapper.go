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
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"net/http"
)

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
	K *ecdsa.PrivateKey
}

func (wr *signingWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	respWrapper := &responseGrabber{}
	wr.H.ServeHTTP(respWrapper, r)
	var b []byte
	if respWrapper.Contents != nil {
		b = respWrapper.Contents.Bytes()
	}
	sig, err := ecSign(b, wr.K)
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

// CreateHTTPSignatureHandler writes this data to an HttpResponse and then add a signature header.
func CreateHTTPSignatureHandler(pkey *ecdsa.PrivateKey, h http.Handler) http.Handler {
	return &signingWrapper{
		H: h,
		K: pkey,
	}
}
