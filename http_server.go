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
	"net/http"

	"github.com/continusec/key-transparency/pb"
	"github.com/continusec/verifiabledatastructures"
	vpb "github.com/continusec/verifiabledatastructures/pb"
	"github.com/gorilla/mux"
)

type HTTPServer struct {
	Service            pb.KeyTransparencyServiceServer
	ContextCreator     verifiabledatastructures.ContextCreator
	PassThroughService vpb.VerifiableDataStructuresServiceServer
}

func (kts *HTTPServer) CreateHandler() http.Handler {
	r := mux.NewRouter()

	// Return the public key used for the VUF
	r.HandleFunc("/v2/config/vufPublicKey", func(w http.ResponseWriter, r *http.Request) {
		ctx := kts.ContextCreator(r)
		resp, err := kts.Service.MapVUFFetchMetadata(ctx, &pb.MapVUFFetchMetadataRequest{})
		if err != nil {

		}
	}).Methods("GET")

	// Return the public key used for server signatures
	r.HandleFunc("/v2/config/serverPublicKey", kts.sendServerPublicKey).Methods("GET")

	// Send short-lived token to email specified - used POST since it does stuff on the server and should not be repeated
	r.HandleFunc("/v2/sendToken/{user:.*}", kts.sendTokenHandler).Methods("POST")

	// Set key
	r.HandleFunc("/v2/publicKey/{user:.*}", kts.setKeyHandler).Methods("PUT")

	// Get key for any value (this rule MUST be before next, since next regex is superset)
	r.HandleFunc("/v2/publicKey/{user:[^/]*}/at/{treesize:[0-9]+}", kts.getSizeKeyHandler).Methods("GET")

	// Get key for head
	r.HandleFunc("/v2/publicKey/{user:.*}", kts.getHeadKeyHandler).Methods("GET")

	// Handle direct operations on underlying map and log - make sure we use a low privileged key
	r.HandleFunc("/{wrappedOp:.*}", verifiabledatastructures.CreateRESTHandler(
		kts.PassThroughService,
		kts.ContextCreator,
	).ServeHTTP).Methods("GET")

	return r
}
