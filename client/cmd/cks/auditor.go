package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/net/context"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/urfave/cli"
)

var (
	ErrVeryBad = errors.New("ErrVeryBad")
)

func audit(db *bolt.DB, c *cli.Context) error {
	vmap, err := getMap()
	if err != nil {
		return err
	}

	prevMapState, err := getCurrentHead("auditedhead")
	if err != nil {
		if confirmIt("No previous audited head found. Start from scratch? (yes/no)") {
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

	if prevMapState != nil && prevMapState.TreeHeadLogTreeHead.TreeSize >= curMapState.TreeHeadLogTreeHead.TreeSize {
		fmt.Println("Previous audited tree head log size is greater than or equal to current - no audit needed.")
		return nil
	} else {
		sequenceNumberPerKey := make(map[string]int64) // we use string instead of []byte since it won't hash
		err = vmap.VerifyMap(context.Background(), prevMapState, curMapState, continusec.RedactedJsonEntryFactory, func(ctx context.Context, idx int64, key []byte, value continusec.VerifiableEntry) error {
			mk := string(key)

			oldSeq, ok := sequenceNumberPerKey[mk]
			if !ok {
				oldSeq = -1 // so that new seq is correctly 0
			}

			expectedSequence := oldSeq + 1

			dd, err := value.Data()
			if err != nil {
				return err
			}

			var pkd PublicKeyData
			err = json.NewDecoder(bytes.NewReader(dd)).Decode(&pkd)
			if err != nil {
				return err
			}

			if pkd.Sequence != expectedSequence {
				return ErrVeryBad
			}

			sequenceNumberPerKey[mk] = expectedSequence

			return nil
		})
		if err != nil {
			return err
		}

		err = setCurrentHead("auditedhead", curMapState)
		if err != nil {
			return err
		}

		fmt.Println("Audit successful.")
		return nil
	}
}
