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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/boltdb/bolt"
	"github.com/urfave/cli"
)

// Print out gossip string suitable for sharing that summarizes every historical value
// present by this client
func showGossip(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 0 {
		return errors.New("unexpected arguments")
	}

	mapState, err := getCurrentHead("head")
	if err != nil {
		return err
	}

	if mapState == nil {
		return errors.New("empty map, nothing to gossip")
	}

	server, err := getServer()
	if err != nil {
		return err
	}

	ce, err := (&cachingVerifyingRT{DB: db}).getValFromCache(fmt.Sprintf("%s/v2/wrappedMap/log/treehead/tree/%d", server, mapState.TreeHeadLogTreeHead.TreeSize))
	if err != nil {
		return err
	}

	buffer := &bytes.Buffer{}
	err = json.NewEncoder(buffer).Encode(&gossip{Signature: ce.Signature, TreeHeadLogTreehead: ce.Data})
	if err != nil {
		return err
	}

	fmt.Println(base64.StdEncoding.EncodeToString(buffer.Bytes()))

	return nil
}
