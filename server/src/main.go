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
	"html/template"
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

	"github.com/BurntSushi/toml"
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

type tomlConfig struct {
	Server     serverConf
	Continusec continusecConf
	SendGrid   sendgridConf
	Crypto     privateKeyConf
}

type serverConf struct {
	BasePath              string `toml:"base_path"`
	DisableAuthentication bool   `toml:"disable_authentication"`
}

type continusecConf struct {
	Account            string
	Map                string
	MutatingKey        string `toml:"mutating_key"`
	LimitedReadOnlyKey string `toml:"readonly_key"`
}

type sendgridConf struct {
	SecretKey     string `toml:"secret_key"`
	FromAddress   string `toml:"from_address"`
	EmailSubject  string `toml:"mail_subject"`
	TokenTemplate string `toml:"token_template"`
}

type privateKeyConf struct {
	ServerPrivateECKey     string `toml:"server_ec_private_key"`
	EmailTokenPrivateECKey string `toml:"email_token_ec_private_key"`
	VufPrivateRsaKey       string `toml:"vuf_rsa_private_key"`
}

var (
	// The signature failed to validate - likely wrong email.
	ErrInvalidSig = errors.New("ErrInvalidSig")

	// The signature is too old
	ErrTTLExpired = errors.New("ErrTTLExpired")

	ErrInvalidKey = errors.New("ErrInvalidKey")
)

const (
	WrappedOp = "/v1/wrappedMap/"
)

func SendMail(sender string, recipients []string, subject, body string, ctx context.Context) error {
	sg := sendgrid.NewSendGridClientWithApiKey(config.SendGrid.SecretKey)
	sg.Client = getHttpClientWithLongerDeadline(ctx)

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

// TokenData is used to form a basic structure that we take the object hash of before signing.
type TokenData struct {
	// Email is the email address this token is valid for
	Email string `json:"email"`

	// TTL is the time (seconds since epoch UTC) until this token is valid. Normally 1 hour after issue.
	TTL int64 `json:"ttl"`
}

// mustReadRSAPrivateKeyFromPEM converts a string that should be a PEM of type "PRIVATE KEY" to an
// actual RSA private key.
func readRSAPrivateKeyFromPEM(s string) (*rsa.PrivateKey, error) {
	var p *pem.Block
	p, _ = pem.Decode([]byte(s))
	if p == nil {
		return nil, ErrInvalidKey
	}

	if !strings.HasSuffix(p.Type, "PRIVATE KEY") {
		return nil, ErrInvalidKey
	}

	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	rv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	return rv, nil
}

// mustReadECPrivateKeyFromPEM converts a string that should be a PEM of type "EC PRIVATE KEY" to an
// actual RSA private key.
func readECPrivateKeyFromPEM(s string) (*ecdsa.PrivateKey, error) {
	var p *pem.Block
	p, _ = pem.Decode([]byte(s))
	if p == nil {
		return nil, ErrInvalidKey
	}

	if !strings.HasSuffix(p.Type, "EC PRIVATE KEY") {
		return nil, ErrInvalidKey
	}

	key, err := x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func sendVUFPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/binary")

	writeAndSign(vufPublicKeyBytes, w)
}

func sendServerPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/binary")

	writeAndSign(serverPublicKeyBytes, w)
}

// handleError logs an error and sets an appropriate HTTP status code.
func handleError(err error, r *http.Request, w http.ResponseWriter) {
	switch err {
	default:
		log.Errorf(appengine.NewContext(r), "Error: %v", err)
		w.WriteHeader(500)
	}
}

func getHttpClientWithLongerDeadline(ctx context.Context) *http.Client {
	cctx, _ := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
	return urlfetch.Client(cctx)
}

// Returns a VerifiableMap object ready for manipulations
func getMapObject(ctx context.Context) *continusec.VerifiableMap {
	return (&continusec.Account{
		Account: config.Continusec.Account,
		Client: continusec.DefaultClient.
			WithHttpClient(getHttpClientWithLongerDeadline(ctx)).
			WithApiKey(config.Continusec.MutatingKey),
	}).VerifiableMap(config.Continusec.Map)
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

	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(&AddEntryResult{
		MutationEntryLeafHash: aer.EntryLeafHash,
	})
	if err != nil {
		handleError(err, r, w)
		return
	}

	// And write the result, which is the leaf hash of the mutation entry.
	w.Header().Set("Content-Type", "text/plain")

	writeAndSign(b.Bytes(), w)

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
		VUFResult:      vufResult,
		AuditPath:      curVal.AuditPath,
		TreeSize:       curVal.TreeSize,
		PublicKeyValue: jd,
	}

	b := &bytes.Buffer{}
	err = json.NewEncoder(b).Encode(result)
	if err != nil {
		handleError(err, r, w)
		return
	}

	// And write the results
	w.Header().Set("Content-Type", "text/plain")

	writeAndSign(b.Bytes(), w)

}

// A token is a base64 of asn1 form of this.
type ECDSASignature struct {
	// R, S are as returned by ecdsa.Sign
	R, S *big.Int
}

// A token is a base64 of asn1 form of this.
type SignedToken struct {
	Signature ECDSASignature
	// TTL is the time when this token expires. Email is not sent with the token, since
	// it is presented along with the set request.
	TTL int64
}

// Returns nil if valid - token should be base64 decoded already.
func validateToken(email string, token []byte) error {
	var sig SignedToken
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

	if ecdsa.Verify(&emailTokenPrivateKey.PublicKey, oh, sig.Signature.R, sig.Signature.S) {
		return nil
	} else {
		return ErrInvalidSig
	}
}

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

	r, s, err := ecdsa.Sign(rand.Reader, emailTokenPrivateKey, oh)
	if err != nil {
		return nil, err
	}

	sig, err := asn1.Marshal(SignedToken{Signature: ECDSASignature{R: r, S: s}, TTL: token.TTL})
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

	message := &bytes.Buffer{}
	err = emailTemplate.Execute(message, map[string]string{
		"BasePath": config.Server.BasePath,
		"Token":    tb64,
		"Email":    username,
	})
	if err != nil {
		handleError(err, r, w)
		return
	}

	err = SendMail(config.SendGrid.FromAddress, []string{username}, config.SendGrid.EmailSubject, string(message.Bytes()), appengine.NewContext(r))
	if err != nil {
		handleError(err, r, w)
		return
	}

	// And write the results
	w.WriteHeader(200)
	w.Write([]byte("Email sent with further instructions.\n"))
}

// Returns the key in a map for a given VUF
func GetKeyForVUF(data []byte) []byte {
	rv := sha256.Sum256(data)
	return rv[:]
}

// Calculated the VUF for a plaintext key
func ApplyVUF(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := rsa.SignPKCS1v15(rand.Reader, vufPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func writeAndSign(contents []byte, w http.ResponseWriter) error {
	sig, err := ecSign(contents, serverPrivateKey)
	if err != nil {
		return err
	}

	w.Header().Set("X-Body-Signature", base64.StdEncoding.EncodeToString(sig))
	_, err = w.Write(contents)

	return err
}

func handleWrappedOperation(w http.ResponseWriter, r *http.Request) {
	ctx := appengine.NewContext(r)

	req, err := http.NewRequest("GET", "https://api.continusec.com/v1/account/"+config.Continusec.Account+"/map/"+config.Continusec.Map+"/"+r.URL.Path[len(WrappedOp):], nil)
	log.Debugf(ctx, "%+v", req)
	if err != nil {
		handleError(err, r, w)
		return
	}
	req.Header.Set("Authorization", "Key "+config.Continusec.LimitedReadOnlyKey)

	resp, err := getHttpClientWithLongerDeadline(ctx).Do(req)
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

	w.Header().Set("x-verified-proof", resp.Header.Get("x-verified-proof"))
	w.Header().Set("x-verified-treesize", resp.Header.Get("x-verified-treesize"))
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	if resp.StatusCode == 200 {
		writeAndSign(contents, w)
	} else {
		w.WriteHeader(resp.StatusCode)
		w.Write(contents)
	}
}

var (
	config               tomlConfig
	emailTemplate        *template.Template
	emailTokenPrivateKey *ecdsa.PrivateKey
	serverPrivateKey     *ecdsa.PrivateKey
	vufPrivateKey        *rsa.PrivateKey

	serverPublicKeyBytes []byte
	vufPublicKeyBytes    []byte
)

func init() {
	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		panic("invalid config file:" + err.Error())
	}

	emailTemplate, err = template.New("master").Parse(config.SendGrid.TokenTemplate)
	if err != nil {
		panic("invalid email template:" + err.Error())
	}

	emailTokenPrivateKey, err = readECPrivateKeyFromPEM(config.Crypto.EmailTokenPrivateECKey)
	if err != nil {
		panic("invalid email token key:" + err.Error())
	}

	serverPrivateKey, err = readECPrivateKeyFromPEM(config.Crypto.ServerPrivateECKey)
	if err != nil {
		panic("invalid server key:" + err.Error())
	}

	vufPrivateKey, err = readRSAPrivateKeyFromPEM(config.Crypto.VufPrivateRsaKey)
	if err != nil {
		panic("invalid vuf key:" + err.Error())
	}

	serverPublicKeyBytes, err = x509.MarshalPKIXPublicKey(&serverPrivateKey.PublicKey)
	if err != nil {
		panic("cannot serialize public key:" + err.Error())
	}

	vufPublicKeyBytes, err = x509.MarshalPKIXPublicKey(&vufPrivateKey.PublicKey)
	if err != nil {
		panic("cannot serialize public key:" + err.Error())
	}

	r := mux.NewRouter()

	// Return the public key used for the VUF
	r.HandleFunc("/v1/config/vufPublicKey", sendVUFPublicKey).Methods("GET")

	// Return the public key used for server signatures
	r.HandleFunc("/v1/config/serverPublicKey", sendServerPublicKey).Methods("GET")

	// Send short-lived token to email specified - used POST since it does stuff on the server and should not be repeated
	r.HandleFunc("/v1/sendToken/{user:.*}", sendTokenHandler).Methods("POST")

	// Set key
	r.HandleFunc("/v1/publicKey/{user:.*}", setKeyHandler).Methods("PUT")

	// Get key for any value (this rule MUST be before next)
	r.HandleFunc("/v1/publicKey/{user:[^/]*}/at/{treesize:[0-9]+}", getSizeKeyHandler).Methods("GET")

	// Get key for head
	r.HandleFunc("/v1/publicKey/{user:.*}", getHeadKeyHandler).Methods("GET")

	// Handle direct operations on underlying map and log - make sure we used a low privileged key
	r.HandleFunc(WrappedOp+"{wrappedOp:.*}", handleWrappedOperation).Methods("GET")

	http.Handle("/", r)
}
