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
	"net/http"
	"os"

	keytransparency "github.com/continusec/key-transparency"
	"github.com/continusec/verifiabledatastructures"
	"github.com/continusec/verifiabledatastructures/pb"
	"google.golang.org/appengine"
)

func init() {
	// Create storage layer for our Verifiable Data Structures service
	db := &keytransparency.AppEngineStorage{}

	// Get signing key
	signingKey := keytransparency.MustCreateECKeyFromPEM(os.Getenv("SERVER_SIGNING_KEY"))

	// Our service
	service := &keytransparency.LocalService{
		BaseURL:         os.Getenv("BASE_URL"),
		VUFKey:          keytransparency.MustCreateRSAKeyFromPEM(os.Getenv("VUF_KEY")),
		MailTokenKey:    keytransparency.MustCreateECKeyFromPEM(os.Getenv("MAIL_TOKEN_KEY")),
		ServerPublicKey: &signingKey.PublicKey,
		Keys: (&verifiabledatastructures.Client{
			Service: (&verifiabledatastructures.LocalService{
				AccessPolicy: &verifiabledatastructures.AnythingGoesOracle{},
				Mutator: &verifiabledatastructures.InstantMutator{
					Writer: db,
				},
				Reader: db,
			}).MustCreate(),
		}).Account("0", "").VerifiableMap("keys"),
		Mailer: &keytransparency.AppEngineMailer{
			Subject: "Key Transparency Token Request",
			From:    os.Getenv("FROM_EMAIL"),
		},
	}

	// Our HTTP handler
	http.Handle("/", keytransparency.CreateHTTPSignatureHandler(signingKey, (&keytransparency.HTTPServer{
		ContextCreator: appengine.NewContext,
		Service:        service,
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
	}).CreateHandler()))
}
