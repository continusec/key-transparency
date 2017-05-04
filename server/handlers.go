/*
   Copyright 2016 Continusec Pty Ltd

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
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp/armor"

	"github.com/continusec/go-client/continusec"
	"github.com/gorilla/mux"
)

// Handle request to send a new token to a given address.
// Currently these tokens are valid for 1 hour.
// If DisableAuthentication is set, then an error response is sent instead.
func sendTokenHandler(w http.ResponseWriter, r *http.Request) {
	if config.Server.DisableAuthentication {
		w.WriteHeader(400)
		w.Write([]byte("Configuration has disabled authentication - no tokens will be sent."))
		return
	}

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

	s := string(message.Bytes())
	s = strings.Replace(s, "&#43;", "+", -1) // TODO: find better way of not escaping +

	err = sendMail(getContext(r), config.SendGrid.FromAddress, []string{username}, config.SendGrid.EmailSubject, s)
	if err != nil {
		handleError(err, r, w)
		return
	}

	// And write the results
	w.WriteHeader(200)
	w.Write([]byte("Email sent with further instructions.\n"))
}

// Respond with a DER-encoded VUF Public Key
func sendVUFPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/binary")

	writeAndSign(vufPublicKeyBytes, w)
}

// Respond with a DER-encoded Server Public Key
func sendServerPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/binary")

	writeAndSign(serverPublicKeyBytes, w)
}

var (
	ErrTooBig = errors.New("ErrTooBig")
)

// Return nil if this is OK to be a value.
// We want there to be at least 1 valid PEM PGP PUBLIC KEY BLOCK,
// and if found, we will just store what we sent to us,
// provided it is less than 1 MB.
func validateData(data []byte) error {
	if len(data) > (1024 * 1024) {
		return ErrTooBig
	}

	p, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return err
	}

	if p == nil {
		return ErrInvalidKey
	}

	if p.Type != "PGP PUBLIC KEY BLOCK" {
		return ErrInvalidKey
	}

	// All good
	return nil
}

// Sets a new public key for a user. Will get the current one from the verifiable map,
// and then issue an update request with an updated sequence number which will shortly
// be sequenced and reflected back in a new map head.
// Unless DisableAuthentication is set, this will check for the presence of a valid token
// for that email address as sent by sendTokenHandler.
func setKeyHandler(w http.ResponseWriter, r *http.Request) {
	// Get the username
	username := mux.Vars(r)["user"]

	// Check if we have a valid token
	if config.Server.DisableAuthentication {
		// if we've chosen to disable authentication, then skip
	} else {
		token, err := base64.StdEncoding.DecodeString(r.Header.Get("Authorization"))
		if err != nil {
			w.WriteHeader(403)
			return
		}
		err = validateToken(username, token)
		if err != nil { // no good, fail
			w.WriteHeader(403)
			return
		}
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

	// Validate the input
	err = validateData(body)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	// Load up the Map
	vmap := getMapObject(getContext(r))

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

		if bytes.Equal(pkd.PGPPublicKey, body) {
			w.WriteHeader(204) // TODO: pick a better header for no action required
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

	// Update the value - will only apply if no-one else modifies.
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

	// And write the result, which is the leaf hash of the mutation entry which can be polled
	// for sequencing against the mutation log if desired.
	w.Header().Set("Content-Type", "text/plain")

	writeAndSign(b.Bytes(), w)
}

// Get the latest data for a map key
func getHeadKeyHandler(w http.ResponseWriter, r *http.Request) {
	getKeyHandler(continusec.Head, w, r)
}

// Get the data for the map key for a specific tree size
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
	vmap := getMapObject(getContext(r))

	// Get the current value - deliberate pick JSON Entry Factory since we want to return raw
	curVal, err := vmap.Get(GetKeyForVUF(vufResult), ts, continusec.JsonEntryFactory)
	if err != nil {
		handleError(err, r, w)
		return
	}

	// Get the public key data response
	jd, err := curVal.Value.Data()
	if err != nil {
		handleError(err, r, w)
		return
	}

	// Formulate our response object
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

// Proxy read-only requests to the underlying map/log structures.
// This uses the LimitedReadOnlyKey which should be configured to allow minimal access.
func handleWrappedOperation(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", config.Continusec.APIBaseURL+"/v1/account/"+config.Continusec.Account+"/map/"+config.Continusec.Map+"/"+r.URL.Path[len(WrappedOp):], nil)
	if err != nil {
		handleError(err, r, w)
		return
	}
	req.Header.Set("Authorization", "Key "+config.Continusec.LimitedReadOnlyKey)

	resp, err := getHttpClient(getContext(r)).Do(req)
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

	actualHeader, ok := resp.Header[http.CanonicalHeaderKey("X-Verified-Proof")]
	if ok {
		w.Header().Set("x-verified-proof", strings.Join(actualHeader, ","))
	}

	actualHeader, ok = resp.Header[http.CanonicalHeaderKey("X-Verified-TreeSize")]
	if ok {
		w.Header().Set("x-verified-treesize", strings.Join(actualHeader, ","))
	}

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	if resp.StatusCode == 200 {
		writeAndSign(contents, w)
	} else {
		w.WriteHeader(resp.StatusCode)
		w.Write(contents)
	}
}
