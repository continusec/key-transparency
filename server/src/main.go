/* Copyright (C) 2016 Continusec Pty Ltd - All Rights Reserved */

package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"

	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"

	"github.com/gorilla/mux"

	"github.com/continusec/go-client/continusec"
	"github.com/continusec/objecthash"
	sendgrid "github.com/sendgrid/sendgrid-go"
)

/*

Useful commands for testing:

# Generate EC public/private key
openssl ecparam -genkey -name prime256v1

# Generate RSA public/private key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048

# Export GPG public key, and send it to the API server:
gpg --export adam@continusec.com | curl -i -X PUT http://localhost:8080/v1/publicKey/adam@continusec.com -d @-

gpg --export adam.eijdenberg@gmail.com | curl -H "Authorization: %s" -i -X PUT http://localhost:8080/v1/publicKey/adam.eijdenberg@gmail.com -d @-


curl http://localhost:8080/v1/publicKey/adam.eijdenberg@gmail.com

get token:

curl -X POST -d "" https://continusec-key-server.appspot.com/v1/sendToken/adam.eijdenberg@gmail.com

*/

const (
	// The Continusec account to use
	ContinusecAccount = "606281927392511840"

	// The Continusec API key to use for getting/setting values directly on the map
	ContinusecSecretKey = "75cc2c8b86e96d1574c209d2ec1d3aa418e2ffd19bcc285e8d67111a4048e991"

	// The Continusec API key to use for read-only operations to the mutation/tree-head logs
	ContinusecPublicKey = "4ac946464f5fa0b150fbf8f99c830302809cc9c4e84ebc1548e2c5ab992d5e28"

	// The name of the map to use
	ContinusecMap = "keys2"

	// SendGrid key
	SendGridEmailSecretKey = "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"

	// From address for sending email token
	EmailFromAddress = "key-transparency-token@continusec.com"

	// Subject
	EmailSubject = "Key Transparency Token Request"

	// Message
	EmailMessage = `Thank you for requesting an authorization token for submitting your key data.

The following token has been generated and is valid for 1 hour:
%s

Example usage (to export your GPG public key):

gpg --export %s | curl -H "Authorization: %s" -i -X PUT https://continusec-key-server.appspot.com/v1/publicKey/%s -d @-

If you didn't make this request, then please ignore this message.

To learn more about Key Transparency, please visit:
https://www.continusec.com/case-studies/key-transparency

Continusec Support`
)

var (
	// VUFPrivateKey is used to create a signature, that forms the basis of the
	// key used to store the public key in the Merkle Tree. We use RSA because this must
	// be deterministic.
	VUFPrivateKey = mustReadRSAPrivateKeyFromPEM("keys/vuf.pem")

	// EmailTokenPrivateKey is used to generate a short lived token to submit a key
	// for a given address. We use EC because it's shorter.
	EmailTokenPrivateKey = mustReadECPrivateKeyFromPEM("keys/emailtoken.pem")
)

var (
	// The signature failed to validate - likely wrong email.
	ErrInvalidSig = errors.New("ErrInvalidSig")

	// The signature is too old
	ErrTTLExpired = errors.New("ErrTTLExpired")
)

const (
	WrappedOp = "/v1/wrappedMap/"
)

func SendMail(sender string, recipients []string, subject, body string, ctx context.Context) error {
	sg := sendgrid.NewSendGridClientWithApiKey(SendGridEmailSecretKey)
	sg.Client = urlfetch.Client(ctx)

	message := sendgrid.NewMail()
	for _, recip := range recipients {
		message.AddTo(recip)
	}
	message.SetSubject(subject)
	message.SetText(body)
	message.SetFrom(sender)

	return sg.Send(message)
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

	// PublicKeyValue is a redacted PublicKeyData field.
	PublicKeyValue interface{} `json:"publicKeyValue"`
}

// AddEntryResult is the data returned when setting a key in the map
type AddEntryResult struct {
	// MutationEntryLeafHash is the leaf hash of the entry added to the mutation log for the map.
	// Once this has been verified to be added to the mutation log for the map, then this entry
	// will be reflected for the map at that size (provided no conflicting operation occurred).
	MutationEntryLeafHash []byte `json:"mutationEntryLeafHash"`
}

// TokenData is used to form a basic structure that we take the object hash of before signing.
type TokenData struct {
	// Email is the email address this token is valid for
	Email string `json:"email"`

	// TTL is the time (seconds since epoch UTC) until this token is valid. Normally 1 hour after issue.
	TTL int64 `json:"ttl"`
}

// mustReadRSAPrivateKeyFromPEM converts a file path that should be a PEM of type "PRIVATE KEY" to an
// actual RSA private key. Panics on any error.
func mustReadRSAPrivateKeyFromPEM(path string) *rsa.PrivateKey {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		panic(4)
	}
	var p *pem.Block
	p, b = pem.Decode(b)
	if p == nil {
		panic(4)
	} else {
		if strings.HasSuffix(p.Type, "PRIVATE KEY") {
			key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
			if err != nil {
				panic(1)
			}
			rv, ok := key.(*rsa.PrivateKey)
			if !ok {
				panic(2)
			}
			return rv
		} else {
			panic(5)
		}
	}
}

// mustReadECPrivateKeyFromPEM converts a file path that should be a PEM of type "EC PRIVATE KEY" to an
// actual RSA private key. Panics on any error.
func mustReadECPrivateKeyFromPEM(path string) *ecdsa.PrivateKey {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		panic(4)
	}
	var p *pem.Block
	p, b = pem.Decode(b)
	if p == nil {
		panic(4)
	} else {
		if strings.HasSuffix(p.Type, "EC PRIVATE KEY") {
			key, err := x509.ParseECPrivateKey(p.Bytes)
			if err != nil {
				panic(1)
			}
			return key
		} else {
			panic(5)
		}
	}
}

// handleError logs an error and sets an appropriate HTTP status code.
func handleError(err error, r *http.Request, w http.ResponseWriter) {
	switch err {
	default:
		log.Errorf(appengine.NewContext(r), "Error: %v", err)
		w.WriteHeader(500)
	}
}

// Returns a VerifiableMap object ready for manipulations
func getMapObject(ctx context.Context) *continusec.VerifiableMap {
	return continusec.NewClient(ContinusecAccount,
		ContinusecSecretKey).WithHttpClient(
		urlfetch.Client(ctx)).VerifiableMap(ContinusecMap)
}

// EmptyLeafHash is the leaf hash of an empty node, pre-calculated since used often.
var EmptyLeafHash = sha256.Sum256([]byte{0})

// Sets a new public key for a user. Will get the current one, and *should* verify that
// the new one is signed by the old one, then assign a new sequence number.
// Requires that the "Authorization" header be set to a value as sent by a previous
// call to /v1/sendToken/... (which has the effect of weakly verifying control of the
// email address).
func setKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Get the username
	username := mux.Vars(r)["user"]

	// Check if we have a valid token
	token, err := base64.StdEncoding.DecodeString(r.Header.Get("Authorization"))
	if err != nil {
		handleError(err, r, w)
		return
	}
	err = validateToken(username, token)
	if err != nil { // no good, fail
		handleError(err, r, w)
		return
	}

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
	nextSequence := int64(0) // unless advised otherwise

	// Get key for VUF
	keyForVuf := GetKeyForVUF(vufResult)

	// Get the current value so that we can pick the next sequence
	curVal, err := vmap.Get(keyForVuf, continusec.Head, continusec.RedactedJsonEntryFactory)
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
		Sequence:      nextSequence,
		Email:         username,
		PGPPublicKey:  body,
		PriorTreeSize: curVal.TreeSize,
	})
	if err != nil {
		handleError(err, r, w)
		return
	}

	// Update the thing - will only apply if no-one else modifies.
	aer, err := vmap.Update(keyForVuf, &continusec.RedactableJsonEntry{JsonBytes: jb}, curVal.Value)
	if err != nil {
		handleError(err, r, w)
		return
	}

	// And write the result, which is the leaf hash of the mutation entry.
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(&AddEntryResult{
		MutationEntryLeafHash: aer.EntryLeafHash,
	})
}

// Get the latest data for a key
func getHeadKeyHandler(w http.ResponseWriter, r *http.Request) {
	getKeyHandler(continusec.Head, w, r)
}

// Get the data for the key for a specific tree size
func getSizeKeyHandler(w http.ResponseWriter, r *http.Request) {
	ts, err := strconv.Atoi(mux.Vars(r)["treesize"])
	if err != nil {
		handleError(err, r, w)
		return
	}

	getKeyHandler(int64(ts), w, r)
}

// Private handler to actually get the data for a given tree size
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
	curVal, err := vmap.Get(GetKeyForVUF(vufResult), ts, continusec.JsonEntryFactory)
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

	result := &GetEntryResult{
		VUFResult: vufResult,
		AuditPath: curVal.AuditPath,
		TreeSize:  curVal.TreeSize,
	}

	if len(jd) > 0 {
		var pkd interface{}
		err = json.Unmarshal(jd, &pkd)
		if err != nil {
			handleError(err, r, w)
			return
		}
		result.PublicKeyValue = &pkd
	}

	// And write the results
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(200)

	json.NewEncoder(w).Encode(result)
}

// A token is a base64 of asn1 form of this.
type ECDSASignature struct {
	// R, S are as returned by ecdsa.Sign
	R, S *big.Int

	// TTL is the time when this token expires. Email is not sent with the token, since
	// it is presented along with the set request.
	TTL int64
}

// Returns nil if valid - token should be base64 decoded already.
func validateToken(email string, token []byte) error {
	var sig ECDSASignature
	_, err := asn1.Unmarshal(token, &sig)
	if err != nil {
		return err
	}

	if time.Now().After(time.Unix(sig.TTL, 0)) {
		return ErrTTLExpired
	}

	td := &TokenData{
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

	if ecdsa.Verify(&EmailTokenPrivateKey.PublicKey, oh, sig.R, sig.S) {
		return nil
	} else {
		return ErrInvalidSig
	}
}

// Creates a new token for the email address and specified TTL.
// Result is to be base64 encoded by caller.
func makeToken(email string, ttl time.Time) ([]byte, error) {
	token := &TokenData{
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

	r, s, err := ecdsa.Sign(rand.Reader, EmailTokenPrivateKey, oh)
	if err != nil {
		return nil, err
	}

	sig, err := asn1.Marshal(ECDSASignature{R: r, S: s, TTL: token.TTL})
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Handle request to send a new token to a given address.
// Currently these tokens are valid for 5 mins only.
func sendTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Get the username
	username := mux.Vars(r)["user"]

	token, err := makeToken(username, time.Now().Add(time.Hour))
	if err != nil {
		handleError(err, r, w)
		return
	}

	tb64 := base64.StdEncoding.EncodeToString(token)

	err = SendMail(EmailFromAddress, []string{username}, EmailSubject, fmt.Sprintf(EmailMessage,
		tb64, username, tb64, username), appengine.NewContext(r))
	if err != nil {
		handleError(err, r, w)
		return
	}

	// And write the results
	w.WriteHeader(200)
	w.Write([]byte("Email sent with further instructions."))
}

// Returns the key in a map for a given VUF
func GetKeyForVUF(data []byte) []byte {
	rv := sha256.Sum256(data)
	return rv[:]
}

// Calculated the VUF for a plaintext key
func ApplyVUF(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, VUFPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func handleWrappedOperation(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	req, err := http.NewRequest("GET", "https://api.continusec.com/v1/account/"+ContinusecAccount+"/map/"+ContinusecMap+"/"+r.URL.Path[len(WrappedOp):], nil)
	log.Debugf(ctx, "%+v", req)
	if err != nil {
		handleError(err, r, w)
		return
	}
	req.Header.Set("Authorization", "Key "+ContinusecPublicKey)

	resp, err := urlfetch.Client(ctx).Do(req)
	if err != nil {
		handleError(err, r, w)
		return
	}

	contents, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		handleError(err, r, w)
		return
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(contents)
}

func init() {
	r := mux.NewRouter()

	// Send short-lived token to email specified - used POST since it does stuff on the server and should not be repeated
	r.HandleFunc("/v1/sendToken/{user:.*}", sendTokenHandler).Methods("POST")

	// Set key
	r.HandleFunc("/v1/publicKey/{user:.*}", setKeyHandler).Methods("PUT")

	// Get key for head
	r.HandleFunc("/v1/publicKey/{user:.*}", getHeadKeyHandler).Methods("GET")

	// Get key for any value
	r.HandleFunc("/v1/publicKey/{user:.*}/at/{treesize:[0-9]+}", getSizeKeyHandler).Methods("GET")

	// Handle direct operations on underlying map and log - make sure we used a low privileged key
	r.HandleFunc(WrappedOp+"{wrappedOp:.*}", handleWrappedOperation).Methods("GET")

	http.Handle("/", r)
}
