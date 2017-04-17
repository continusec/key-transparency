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
	"github.com/continusec/go-client/continusec"
	"github.com/urfave/cli"
)

// Attempt to verify gossip data. If we have a full audit trail, easy.
func verifyGossip(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 1 {
		return errors.New("expecting base-64 JSON gossip data as input")
	}

	b64Gossip := c.Args().Get(0)
	jsonGossip, err := base64.StdEncoding.DecodeString(b64Gossip)
	if err != nil {
		return err
	}
	var gos gossip
	err = json.NewDecoder(bytes.NewReader([]byte(jsonGossip))).Decode(&gos)
	if err != nil {
		return err
	}

	// verify signature
	pubKey, err := getPubKey(db)
	if err != nil {
		return err
	}
	err = verifySignedData(gos.TreeHeadLogTreehead, gos.Signature, pubKey)
	if err != nil {
		return err
	}
	fmt.Println("Verified signature against our stored public key.")

	var tsr treeSizeResponse
	err = json.NewDecoder(bytes.NewReader(gos.TreeHeadLogTreehead)).Decode(&tsr)
	if err != nil {
		return err
	}

	theirLogTreeHead := &continusec.LogTreeHead{
		TreeSize: tsr.TreeSize,
		RootHash: tsr.Hash,
	}

	ourAuditedMapTreeState, err := getCurrentHead("auditedhead")
	if err != nil {
		return errors.New("no previous audited head found - run: cks audit")
	}

	vmap, err := getMap()
	if err != nil {
		return err
	}

	ourEquiv, err := vmap.TreeHeadLog().VerifiedTreeHead(&ourAuditedMapTreeState.TreeHeadLogTreeHead, theirLogTreeHead.TreeSize)
	if err != nil {
		return err
	}

	if ourEquiv.TreeSize == theirLogTreeHead.TreeSize && bytes.Equal(ourEquiv.RootHash, theirLogTreeHead.RootHash) {
		if theirLogTreeHead.TreeSize <= ourAuditedMapTreeState.TreeHeadLogTreeHead.TreeSize {
			fmt.Println("Success. Their gossip is consistent with, and within, our already audited view.")
		} else {
			fmt.Println("Partial Success. Their gossip is consistent with our audited view, but our audit is not complete for that tree head log size. Run 'cks audit' again then retry.")
		}
		return nil
	} else {
		return errors.New("FAILURE - unable to verify consistency with our log tree head")
	}
}
