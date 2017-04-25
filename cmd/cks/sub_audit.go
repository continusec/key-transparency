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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/boltdb/bolt"
	kpb "github.com/continusec/key-transparency/pb"
	"github.com/continusec/verifiabledatastructures"
	"github.com/continusec/verifiabledatastructures/pb"
	"github.com/urfave/cli"
	"golang.org/x/net/context"
)

// Audit, by fetching all mutation log entries, the entire map. This simplistic implementation
// does so in-memory, so won't scale to huge maps.
func audit(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 0 {
		return errors.New("unexpected arguments")
	}

	vmap, err := getMap()
	if err != nil {
		return err
	}

	prevMapState, err := getCurrentHead("auditedhead")
	if err != nil {
		if c.Bool("yes") || confirmIt("No previous audited head found. Start from scratch? Will download *all* mutation entries (yes/no)") {
			// all good, continue
			prevMapState = nil
		} else {
			return err
		}
	}

	curMapState, err := getCurrentHead("head")
	if err != nil {
		return err
	}

	if curMapState == nil {
		return errors.New("Map state is empty - run cks update first")
	}

	if prevMapState != nil && prevMapState.TreeHeadLogTreeHead.TreeSize >= curMapState.TreeHeadLogTreeHead.TreeSize {
		return fmt.Errorf("previous audited tree head log size (%d) is greater than or equal to current - no audit needed", curMapState.TreeHeadLogTreeHead.TreeSize)
	}
	sequenceNumberPerKey := make(map[string]int64) // we use string instead of []byte since it won't hash
	err = vmap.VerifyMap(context.Background(), prevMapState, curMapState, verifiabledatastructures.ValidateJSONLeafData, func(ctx context.Context, idx int64, key []byte, value *pb.LeafData) error {
		mk := string(key)

		oldSeq, ok := sequenceNumberPerKey[mk]
		if !ok {
			oldSeq = -1 // so that new seq is correctly 0
		}

		expectedSequence := oldSeq + 1

		shedBytes, err := verifiabledatastructures.ShedRedactedJSONFields(value.ExtraData)
		if err != nil {
			return errors.New("Unable to properly decode redacted field")
		}

		var pkd kpb.VersionedKeyData
		err = json.NewDecoder(bytes.NewReader(shedBytes)).Decode(&pkd)
		if err != nil {
			return err
		}

		if pkd.Sequence != expectedSequence {
			return errors.New("Improper operation of map detected - received unexpected sequence number for a user")
		}

		sequenceNumberPerKey[mk] = expectedSequence

		return nil
	})
	if err != nil {
		return errors.New("Error verifying correct operation of map: " + err.Error())
	}

	err = setCurrentHead("auditedhead", curMapState)
	if err != nil {
		return err
	}

	fmt.Printf("Audit successful to tree head log size of %d.\n", curMapState.TreeHeadLogTreeHead.TreeSize)
	return nil
}
