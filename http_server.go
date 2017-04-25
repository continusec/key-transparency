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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/continusec/key-transparency/pb"
	"github.com/continusec/verifiabledatastructures"
	vpb "github.com/continusec/verifiabledatastructures/pb"
	"github.com/gorilla/mux"
)

// HTTPServer creates an HTTP endpoint for the given service, including pass-through as needed to the
// underlying map API
type HTTPServer struct {
	Service            pb.KeyTransparencyServiceServer
	ContextCreator     verifiabledatastructures.ContextCreator
	PassThroughService vpb.VerifiableDataStructuresServiceServer
}

func writeResponseHeader(w http.ResponseWriter, err error) {
	if err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	s, ok := status.FromError(err)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch s.Code() {
	case codes.PermissionDenied:
		w.WriteHeader(http.StatusUnauthorized)
	case codes.InvalidArgument:
		w.WriteHeader(http.StatusBadRequest)
	case codes.NotFound:
		w.WriteHeader(http.StatusNotFound)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// CreateHandler creates the actual handler
func (kts *HTTPServer) CreateHandler() http.Handler {
	r := mux.NewRouter()

	// Return the public key used for the VUF
	r.HandleFunc("/v2/config/vufPublicKey", func(w http.ResponseWriter, r *http.Request) {
		resp, err := kts.Service.MapVUFFetchMetadata(kts.ContextCreator(r), &pb.MapVUFFetchMetadataRequest{})
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/binary")

		w.Write(resp.VufPublicKey)
	}).Methods("GET")

	// Return the public key used for server signatures
	r.HandleFunc("/v2/config/serverPublicKey", func(w http.ResponseWriter, r *http.Request) {
		resp, err := kts.Service.MapVUFFetchMetadata(kts.ContextCreator(r), &pb.MapVUFFetchMetadataRequest{})
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/binary")
		w.Write(resp.ServerPublicKey)
	}).Methods("GET")

	// Send short-lived token to email specified - used POST since it does stuff on the server and should not be repeated
	r.HandleFunc("/v2/sendToken/{user:.*}", func(w http.ResponseWriter, r *http.Request) {
		_, err := kts.Service.MailToken(kts.ContextCreator(r), &pb.MailTokenRequest{
			Email: mux.Vars(r)["user"],
		})
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		w.Write([]byte("Email sent with further instructions."))
	}).Methods("POST")

	// Set key
	r.HandleFunc("/v2/publicKey/{user:.*}", func(w http.ResponseWriter, r *http.Request) {
		// Read the body, this should be DER encoded PGP Public Key - bytes, not PEM.
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		r.Body.Close()
		resp, err := kts.Service.MapVUFSetValue(kts.ContextCreator(r), &pb.MapVUFSetKeyRequest{
			Key:   []byte(mux.Vars(r)["user"]),
			Token: r.Header.Get("Authorization"),
			Value: body,
		})
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/json")
		json.NewEncoder(w).Encode(resp)
	}).Methods("PUT")

	// Get key for any value (this rule MUST be before next, since next regex is superset)
	r.HandleFunc("/v2/publicKey/{user:[^/]*}/at/{treesize:[0-9]+}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		ts, err := strconv.Atoi(vars["treesize"])
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		resp, err := kts.Service.MapVUFGetValue(kts.ContextCreator(r), &pb.MapVUFGetKeyRequest{
			Key:      []byte(vars["user"]),
			TreeSize: int64(ts),
		})
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/json")
		json.NewEncoder(w).Encode(resp)
	}).Methods("GET")

	// Get key for head
	r.HandleFunc("/v2/publicKey/{user:.*}", func(w http.ResponseWriter, r *http.Request) {
		resp, err := kts.Service.MapVUFGetValue(kts.ContextCreator(r), &pb.MapVUFGetKeyRequest{
			Key:      []byte(mux.Vars(r)["user"]),
			TreeSize: verifiabledatastructures.Head,
		})
		if err != nil {
			writeResponseHeader(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/json")
		json.NewEncoder(w).Encode(resp)
	}).Methods("GET")

	// Handle direct operations on underlying map and log - make sure we use a low privileged key
	r.HandleFunc("/{wrappedOp:.*}", verifiabledatastructures.CreateRESTHandler(
		kts.PassThroughService,
		kts.ContextCreator,
	).ServeHTTP).Methods("GET")

	return r
}
