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
	"fmt"
	"net/http"

	"github.com/continusec/verifiabledatastructures/api"
	"github.com/continusec/verifiabledatastructures/apife"
	"github.com/continusec/verifiabledatastructures/kvstore"
	"github.com/gorilla/mux"
)

// Load the config file and start HTTP server for a Key Transparency server.
func init() {
	err := loadConfigFile()
	if err != nil {
		panic("error initializing:" + err.Error())
	}

	// Embed our our Verifiable Data Structures service
	db := &kvstore.TransientHashMapStorage{}
	mapService = &api.LocalService{
		AccessPolicy: &api.StaticOracle{},
		Mutator: &api.InstantMutator{
			Writer: db,
		},
		Reader: db,
	}
	readOnlyMapService := &api.LocalService{
		AccessPolicy: &api.StaticOracle{},
		Reader:       db,
	}

	r := mux.NewRouter()

	// Return the public key used for the VUF
	r.HandleFunc("/v2/config/vufPublicKey", sendVUFPublicKey).Methods("GET")

	// Return the public key used for server signatures
	r.HandleFunc("/v2/config/serverPublicKey", sendServerPublicKey).Methods("GET")

	// Send short-lived token to email specified - used POST since it does stuff on the server and should not be repeated
	r.HandleFunc("/v2/sendToken/{user:.*}", sendTokenHandler).Methods("POST")

	// Set key
	r.HandleFunc("/v2/publicKey/{user:.*}", setKeyHandler).Methods("PUT")

	// Get key for any value (this rule MUST be before next, since next regex is superset)
	r.HandleFunc("/v2/publicKey/{user:[^/]*}/at/{treesize:[0-9]+}", getSizeKeyHandler).Methods("GET")

	// Get key for head
	r.HandleFunc("/v2/publicKey/{user:.*}", getHeadKeyHandler).Methods("GET")

	// Handle direct operations on underlying map and log - make sure we use a low privileged key
	r.HandleFunc("/{wrappedOp:.*}", apife.CreateRESTHandler(readOnlyMapService).ServeHTTP).Methods("GET")

	http.Handle("/", r)
}

// Main method included so that this can be run without Google App Engine if desired.
// e.g.
// cd server/src
// GOPATH=$PWD/../vendor:$PWD go run *.go

var (
	mapService *api.LocalService
)

func main() {
	fmt.Println("Serving...")
	http.ListenAndServe(":8082", nil)
}
