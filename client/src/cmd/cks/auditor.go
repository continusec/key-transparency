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

	treeHeadLogHead, err := vmap.TreeHeadLog().VerifiedLatestTreeHead(nil)
	if err != nil {
		return err
	}

	sequenceNumberPerKey := make(map[string]int64) // we use string instead of []byte since it won't hash
	err = vmap.TreeHeadLog().VerifyEntries(context.Background(), nil, treeHeadLogHead, continusec.JsonEntryFactory, vmap.CreateInMemoryTreeHeadLogAuditor(
		continusec.RedactedJsonEntryFactory, func(ctx context.Context, idx int64, mutation *continusec.MapMutation, value continusec.VerifiableEntry) error {
			mk := string(mutation.Key)

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
		}),
	)
	if err != nil {
		return err
	}

	fmt.Println("Success!")

	return nil
}
