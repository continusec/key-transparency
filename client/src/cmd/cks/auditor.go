package main

import (
	"fmt"

	"golang.org/x/net/context"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/urfave/cli"
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

	ctx := context.Background()

	err = vmap.TreeHeadLog().VerifyEntries(ctx, nil, treeHeadLogHead, continusec.JsonEntryFactory, CreateInMemoryTreeHeadLogAuditFunction(ctx, vmap))
	if err != nil {
		return err
	}

	fmt.Println("Success!")

	return nil
}
