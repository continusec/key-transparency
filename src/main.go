/* Copyright (C) 2016 Continusec Pty Ltd - All Rights Reserved */

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// openssl ecparam -genkey -name prime256v1
// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
var (
	// Test key, replace later.
	VUFPrivateKey = readRSAPrivateKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
`))
)

func readRSAPrivateKeyFromPEM(b []byte) *rsa.PrivateKey {
	for len(b) > 0 {
		var p *pem.Block
		p, b = pem.Decode(b)
		if p == nil {
			return nil
		} else {
			if strings.HasSuffix(p.Type, "PRIVATE KEY") {
				key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
				if err != nil {
					return nil
				}
				rv, ok := key.(*rsa.PrivateKey)
				if !ok {
					return nil
				}
				return rv
			}
		}
	}
	return nil
}

func setKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	w.Write([]byte(fmt.Sprintf("got >%s<\n", vars["user"])))
}

func getKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	username := []byte(vars["user"])

	hashedInput := sha256.Sum256(username)
	sig, err := rsa.SignPKCS1v15(rand.Reader, VUFPrivateKey, crypto.SHA256, hashedInput[:])
	if err != nil {
		return
	}

	hashedSig := sha256.Sum256(sig)

	w.Write([]byte(fmt.Sprintf("Signature: %x\n\n%x\n", hashedSig, sig)))

}

func init() {
	r := mux.NewRouter()

	r.HandleFunc("/v1/publicKey/{user:.*}", setKeyHandler).Methods("PUT")
	r.HandleFunc("/v1/publicKey/{user:.*}", getKeyHandler).Methods("GET")

	http.Handle("/", r)
}
