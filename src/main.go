/* Copyright (C) 2016 Continusec Pty Ltd - All Rights Reserved */

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/net/context"

	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"

	"github.com/gorilla/mux"

	"github.com/continusec/go-client/continusec"
)

// openssl ecparam -genkey -name prime256v1
// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
// gpg --export adam@continusec.com | curl -X PUT http://localhost:8080/v1/publicKey/adam@continusec.com -D -
var (
	// Test key, replace later.
	VUFPrivateKey = readRSAPrivateKeyFromPEM([]byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDHpyipt0nlbhAt
yP8gATh/GoHuvXOr+HPUi+k589BjGRlAfpLk77YEP7MFZT0WTZ8DdIG1uZFyw37a
e1b2+XY2xgJOahNOm2ZYoAyW9DSdPrl8bt7fz8Ub0QgAYuJLGQlzzhjjs75QKm8b
KDORxOJviw0WVgREIy2gvSsxKGyZDx7q0Qqlu7qSPwR33geRCOVdPRnJ8hEJ0Zg3
8NRTlDCCJd71ExdgUkXBjBCfXkX8rkpc8Mlf22FJbnvH6CpUpqM/Z4gu55U3vKiC
10Bwr4xrXUAbylfXPF5LOCiccmErkhDFsRXGNQykB2FIDrfePWp0O8Gb8wNYLYQ2
I0JuiUxhAgMBAAECggEAQ7WrErO4efizv/NUorQHRwPkYOUbX40pK0Iv3JmVaKZQ
bBEBHGc3YYWA3ymQaAn3DaLrgofmjfdDBDGkMqozryvECHftCFGnihLtchxr45As
M8keCOVbwa1Ie2kNuc5J6F5TDpYcyu85MwqVQrB04sNTsumFFN6hUMwW49sDyXw/
jNlrsdH2UOx3qpHEVBuBJ0YASr6fQR8gWLXf9lntf3KDh5tkBlVyk5itSKzVidl0
SsFEAioNg1M2ETzNPnfjy24mRxDLDHinLxC/SdlvnFcI265HLkdDvLLBho58HgEA
vqhWjDD70uHcjnDHCreB7BVEF575iqxL+Z2lJcwNYQKBgQDzN5pwMZsXIOCtoLQl
NjnqruNvw+LFFS7O20PMTGz21dCBNdxPWczqG/4CG8gW0ov9kVSJ/iKc2ZcPpfDm
YngSDsJj4bvkF0ax+M5msMM6Xk465v/ZbRh+dt8XCygdgVyCY9hwaAoCHnNlFFjC
GQUrXZGy9PJ5uzQhdWAnrVNh/QKBgQDSJWo+dMyrnEaVDIt0Z6ohR9ONlqt1VNSH
EOhdU/Twctu5c8KdV8CSwpDhR1Kpu1GpGTlYSlD+VW8NipX0mFnlHkk1Sb++Vb8n
FFgRTk0CWUcTjKkaxvKH5rO2iW9Giew5RI4QdN0ztjvg7H2qcr6EM5V75vvqvMQM
vLw1Osf/NQKBgD1peNGDdQmt/41X2qTawF0Fs9/wsj3ZT2xj6QaY9ZqN+ovlsa9H
mXozfzvBEBDTMQ3huFrvlIXOW1pUKDPEAVVt7J+TzAGX7v3ZOSSs1V7TmSU+VrPr
3BdypHoJEyQAGf/CflBDtOM8FR8cuByqfKeqhLOPLfqWzl70aEcceMVxAoGAdU+P
rMf1DYPS3xe+rb/E+IkpLuxCUOCHN9MXdCoPHT9xK2jU5pL7HLJiwG/ZVIkOQBCl
s4ThC+nTccLAjWeTH1U11vqRgIZLjFxOAXMtiDcgd2hZampPL9B42FiGduE9roZ3
q/YhGeIMMTazvDgL5K8LLry2OscfxmCBzFFBHlUCgYEA6UZIovezWwyvJi/Zxm4r
4gWwmngYJUhM1BCI51qlGIA2BnGWOwDG3NSPec0a5kNKNIQAhL1+C0arsUKTUlg1
fiS1P7W7Y4r1KN0V8r3NvJ0Gwn5XfAwDPhY0hTyd1y/6zgVizTf2xlr1XAiFXjif
1TCo6zBjbVZoMrX3jFXfdGs=
-----END PRIVATE KEY-----
`))
)

type PublicKeyData struct {
	Sequence     int    `json:"sequence"`
	Email        string `json:"email"`
	PGPPublicKey []byte `json:"pgpPublicKey"`
}

type GetEntryResult struct {
	VUFResult      []byte      `json:"vufResult"`
	AuditPath      [][]byte    `json:"auditPath"`
	TreeSize       int64       `json:"treeSize"`
	PublicKeyValue interface{} `json:"publicKeyValue"`
}

type AddEntryResult struct {
	MutationEntryLeafHash []byte `json:"mutationEntryLeafHash"`
}

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

func handleError(err error, r *http.Request, w http.ResponseWriter) {
	switch err {
	default:
		log.Errorf(appengine.NewContext(r), "Error: %v", err)
		w.WriteHeader(500)
	}
}

func getMapObject(ctx context.Context) *continusec.VerifiableMap {
	return continusec.NewClient("606281927392511840",
		"75cc2c8b86e96d1574c209d2ec1d3aa418e2ffd19bcc285e8d67111a4048e991").WithHttpClient(
		urlfetch.Client(ctx)).VerifiableMap("keys")
}

var EmptyLeafHash = sha256.Sum256([]byte{0})

func setKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Get the username
	username := mux.Vars(r)["user"]

	// Apply the vuf to the username
	vufResult, err := ApplyVUF([]byte(username))
	if err != nil {
		handleError(err, r, w)
		return
	}

	// Read the body, this should be DER encoded PGP Public Key - bytes, not PEM.
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		handleError(err, r, w)
		return
	}

	// Load up the Map
	ctx := appengine.NewContext(r)
	vmap := getMapObject(ctx)

	// Next sequence
	nextSequence := 0 // unless advised otherwise

	// Get the current value so that we can pick the next sequence
	curVal, err := vmap.Get(vufResult, continusec.Head, continusec.RedactedJsonEntryFactory)
	if err != nil {
		handleError(err, r, w)
		return
	}

	// Get the previous hash, since we'll need soon
	prevHash, err := curVal.Value.LeafHash()
	if err != nil {
		handleError(err, r, w)
		return
	}

	// If the prev hash IS NOT empty (if it is, we already like the default val of 0)
	if !bytes.Equal(EmptyLeafHash[:], prevHash) {
		ed, err := curVal.Value.Data()
		if err != nil {
			handleError(err, r, w)
			return
		}
		// If we managed to get the value, then let's decode:
		var pkd PublicKeyData
		err = json.Unmarshal(ed, &pkd)
		if err != nil {
			handleError(err, r, w)
			return
		}

		nextSequence = pkd.Sequence + 1
	}

	// Construct new data
	jb, err := json.Marshal(&PublicKeyData{
		Sequence:     nextSequence,
		Email:        username,
		PGPPublicKey: body,
	})
	if err != nil {
		handleError(err, r, w)
		return
	}

	// Set the thing.
	aer, err := vmap.Set(vufResult, &continusec.RedactableJsonEntry{JsonBytes: jb})
	if err != nil {
		handleError(err, r, w)
		return
	}

	// And write the results
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&AddEntryResult{MutationEntryLeafHash: aer.EntryLeafHash})
}

func getHeadKeyHandler(w http.ResponseWriter, r *http.Request) {
	getKeyHandler(continusec.Head, w, r)
}

func getSizeKeyHandler(w http.ResponseWriter, r *http.Request) {
	ts, err := strconv.Atoi(mux.Vars(r)["treesize"])
	if err != nil {
		handleError(err, r, w)
		return
	}

	getKeyHandler(int64(ts), w, r)
}

func getKeyHandler(ts int64, w http.ResponseWriter, r *http.Request) {
	// Get the username
	username := mux.Vars(r)["user"]

	// Apply the vuf to the username
	vufResult, err := ApplyVUF([]byte(username))
	if err != nil {
		handleError(err, r, w)
		return
	}

	// Load up the Map
	ctx := appengine.NewContext(r)
	vmap := getMapObject(ctx)

	// Get the current value - deliberate pick JSON Entry Factory since we want to return raw
	curVal, err := vmap.Get(vufResult, ts, continusec.JsonEntryFactory)
	if err != nil {
		handleError(err, r, w)
		return
	}

	// PKD
	jd, err := curVal.Value.Data()
	if err != nil {
		handleError(err, r, w)
		return
	}

	var pkd interface{}
	err = json.Unmarshal(jd, &pkd)
	if err != nil {
		handleError(err, r, w)
		return
	}

	// And write the results
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&GetEntryResult{
		VUFResult:      vufResult,
		AuditPath:      curVal.AuditPath,
		TreeSize:       curVal.TreeSize,
		PublicKeyValue: &pkd,
	})
}

func ApplyVUF(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, VUFPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func init() {
	r := mux.NewRouter()

	r.HandleFunc("/v1/publicKey/{user:.*}", setKeyHandler).Methods("PUT")
	r.HandleFunc("/v1/publicKey/{user:.*}", getHeadKeyHandler).Methods("GET")
	r.HandleFunc("/v1/publicKey/{user:.*}/at/{treesize:[0-9]+}", getSizeKeyHandler).Methods("GET")

	http.Handle("/", r)
}
