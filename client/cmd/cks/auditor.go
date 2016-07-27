package main

import (
	"bytes"
	"encoding/base64"
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

type treeSizeResponse struct {
	TreeSize int64  `json:"tree_size"`
	Hash     []byte `json:"tree_hash"`
}

func verifyGossip(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 1 {
		return cli.NewExitError("expecting base-64 JSON gossip data as input", 1)
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
		return cli.NewExitError("no previous audited head found - run: cks audit", 8)
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
		return cli.NewExitError("FAILURE - unable to verify consistency with our log tree head", 8)
	}
}

func audit(db *bolt.DB, c *cli.Context) error {
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

	if prevMapState != nil && prevMapState.TreeHeadLogTreeHead.TreeSize >= curMapState.TreeHeadLogTreeHead.TreeSize {
		fmt.Printf("Previous audited tree head log size (%d) is greater than or equal to current - no audit needed.\n", curMapState.TreeHeadLogTreeHead.TreeSize)
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

		fmt.Printf("Audit successful to tree head log size of %d.\n", curMapState.TreeHeadLogTreeHead.TreeSize)
		return nil
	}
}
