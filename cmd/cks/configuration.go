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

	"github.com/boltdb/bolt"
	"github.com/continusec/verifiabledatastructures"
)

// Return stored public key for server
func getPubKey(db *bolt.DB) ([]byte, error) {
	var pubKey []byte
	err := db.View(func(tx *bolt.Tx) error {
		pubKey = tx.Bucket([]byte("conf")).Get([]byte("serverKey"))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

// Return configured server
func getServer() (string, error) {
	db, err := GetDB()
	if err != nil {
		return "", err
	}
	var server string
	err = db.View(func(tx *bolt.Tx) error {
		server = string(tx.Bucket([]byte("conf")).Get([]byte("server")))
		return nil
	})
	if err != nil {
		return "", err
	}
	return server, nil
}

// Return versifiable map with our special wrapping, verifiying, caching client for the configured
// server.
func getMap() (*verifiabledatastructures.VerifiableMap, error) {
	db, err := GetDB()
	if err != nil {
		return nil, err
	}
	server, err := getServer()
	if err != nil {
		return nil, err
	}
	return (&verifiabledatastructures.Client{
		Service: (&verifiabledatastructures.HTTPRESTClient{
			BaseURL:    server,
			HTTPClient: &http.Client{Transport: &CachingVerifyingRT{DB: db}},
		}).MustDial(),
	}).Account("0", "client").VerifiableMap("keys"), nil
}
