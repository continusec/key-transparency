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

	"github.com/continusec/verifiabledatastructures"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/gorilla/mux"
	"google.golang.org/appengine"
)

var (
	mapService *verifiabledatastructures.Client
)

type KeyTransparencyServer struct {
	Client             *verifiabledatastructures.Client
	PassThroughService pb.VerifiableDataStructuresServiceServer
	ContextCreator     verifiabledatastructures.ContextCreator
}

func (kts *KeyTransparencyServer) CreateHandler() http.Handler {
	r := mux.NewRouter()

	// Return the public key used for the VUF
	r.HandleFunc("/v2/config/vufPublicKey", kts.sendVUFPublicKey).Methods("GET")

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

	return signItHandler(r)
}

// Load the config file and start HTTP server for a Key Transparency server.
func init() {
	err := loadConfigFile()
	if err != nil {
		panic("error initializing:" + err.Error())
	}

	// Embed our our Verifiable Data Structures service
	db := &AppEngineStorage{}

	http.Handle("/", (&KeyTransparencyServer{
		ContextCreator: appengine.NewContext,
		PassThroughService: (&verifiabledatastructures.LocalService{
			AccessPolicy: &verifiabledatastructures.StaticOracle{
				Policy: []*pb.ResourceAccount{
					{
						Id: "0",
						Policy: []*pb.AccessPolicy{
							{
								ApiKey: "*",
								Permissions: []pb.Permission{
									pb.Permission_PERM_MAP_GET_VALUE,
									pb.Permission_PERM_MAP_MUTATION_READ_ENTRY,
									pb.Permission_PERM_MAP_MUTATION_READ_HASH,
								},
								NameMatch:     "keys",
								AllowedFields: []string{"sequence"}, // the only field that auditors need
							},
						},
					},
				},
			},
			Reader: db,
		}).MustCreate(),
		Client: &verifiabledatastructures.Client{
			Service: (&verifiabledatastructures.LocalService{
				AccessPolicy: &verifiabledatastructures.AnythingGoesOracle{},
				Mutator: &verifiabledatastructures.InstantMutator{
					Writer: db,
				},
				Reader: db,
			}).MustCreate(),
		},
	}).CreateHandler())
}

// Main method included so that this can be run without Google App Engine if desired.
// e.g.
// cd server/src
// GOPATH=$PWD/../vendor:$PWD go run *.go

func main() {
	fmt.Println("Serving...")
	http.ListenAndServe(":8082", nil)
}
