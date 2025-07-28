package main

import (
	"net/http"
	"time"

	"github.com/continusec/go-client/continusec"
	"github.com/continusec/verifiabledatastructures/mutator/instant"
	"github.com/continusec/verifiabledatastructures/oracle/policy"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/continusec/verifiabledatastructures/server/httprest"
	"github.com/continusec/verifiabledatastructures/storage/bolt"
	"github.com/continusec/verifiabledatastructures/verifiable"
	"github.com/sirupsen/logrus"
)

func startLocalServer() {
	db := &bolt.Storage{
		Path: config.Continusec.LocalBoltPath,
	}
	defer db.Close() // release file locks

	localBind := ":7422"

	go httprest.StartServer(&pb.ServerConfig{
		RestListenBind:           localBind,
		InsecureServerForTesting: true,
	}, (&verifiable.Service{
		AccessPolicy: &policy.Static{
			Policy: []*pb.ResourceAccount{
				{
					Id: "123456",
					Policy: []*pb.AccessPolicy{
						{
							ApiKey:    "bootstrap",
							NameMatch: "keys",
							Permissions: []pb.Permission{
								pb.Permission_PERM_MAP_CREATE,
							},
						},
						{
							ApiKey:    "mutating",
							NameMatch: "keys",
							AllowedFields: []string{
								"*",
							},
							Permissions: []pb.Permission{
								pb.Permission_PERM_MAP_SET_VALUE,
								pb.Permission_PERM_MAP_GET_VALUE,
							},
						},
						{
							ApiKey:    "readonly",
							NameMatch: "keys",
							AllowedFields: []string{
								"sequence",
								"action",
								"key",
								"value",
								"previous",
								"timestamp",
								"mutation_log/*",
								"map_hash",
							},
							Permissions: []pb.Permission{
								pb.Permission_PERM_MAP_GET_VALUE,
								pb.Permission_PERM_MAP_MUTATION_READ_ENTRY,
								pb.Permission_PERM_MAP_MUTATION_READ_HASH,
							},
						},
					},
				},
			},
		},
		Mutator: &instant.Mutator{
			Writer: db,
		},
		Reader: db,
	}).MustCreate())

	time.Sleep(100 * time.Millisecond) // TODO, do better than sleep to wait for serving to be ready
	// TODO do better and close DB when done

	config.Continusec.MutatingKey = "mutating"
	config.Continusec.LimitedReadOnlyKey = "readonly"
	config.Continusec.Account = "123456"
	config.Continusec.Map = "keys"
	config.Continusec.APIBaseURL = "http://localhost" + localBind

	if err := (&continusec.Account{
		Account: config.Continusec.Account,
		Client: continusec.DefaultClient.
			WithHttpClient(http.DefaultClient).
			WithBaseUrl(config.Continusec.APIBaseURL + "/v2").
			WithApiKey("bootstrap"),
	}).VerifiableMap(config.Continusec.Map).Create(); err != nil {
		logrus.Errorf("error attempting to bootstrap map: %v", err)
	}
}
