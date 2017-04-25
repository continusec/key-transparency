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
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/boltdb/bolt"
	"github.com/continusec/key-transparency/pb"
	"github.com/urfave/cli"
)

// Request that the server mail a token to the user
func mailToken(db *bolt.DB, c *cli.Context) error {
	if c.NArg() != 1 {
		return errors.New("exactly one email address must be specified")
	}
	emailAddress := c.Args().Get(0)

	if strings.Index(emailAddress, "@") == -1 {
		return errors.New("email address not recognized")
	}

	if c.Bool("yes") || confirmIt(fmt.Sprintf("Are you sure you want to generate and send a token to address (%s)? Please only do so if you own that email account.", emailAddress)) {
		fmt.Printf("Sending mail to %s with token...\n", emailAddress)

		server, err := getKTClient("")
		if err != nil {
			return err
		}

		_, err = server.MailToken(context.Background(), &pb.MailTokenRequest{
			Email: emailAddress,
		})
		if err != nil {
			return err
		}

		fmt.Printf("Success. See email for further instructions.\n")
	} else {
		fmt.Printf("Cancelled.\n")
	}
	return nil
}
