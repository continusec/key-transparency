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
	"os"
	"time"

	"github.com/urfave/cli"
)

// Entry point for the application
func main() {
	app := cli.NewApp()

	app.Name = "cks"
	app.Usage = "utility for interaction with the Continusec Key Server"
	app.Version = "v0.2"
	app.Compiled = time.Now()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Adam Eijdenberg",
			Email: "adam@continusec.com",
		},
	}
	app.Copyright = "(c) 2017 Continusec Pty Ltd"

	app.Commands = []cli.Command{
		{
			Name:   "init",
			Usage:  "Initialize local database and state",
			Action: initNewServer,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "server",
					Value: "https://continusec-key-server.appspot.com",
					Usage: "API endpoint to use (leave default unless developing your own)",
				},
				cli.BoolFlag{
					Name:  "yes",
					Usage: "Bypass confirmation prompts",
				},
			},
		},
		{
			Name:   "status",
			Usage:  "Show revision of map in effect",
			Action: stdCmd(showStatus),
		},
		{
			Name:   "gossip",
			Usage:  "Print data suitable for gossip - will always be latest tree head log tree head",
			Action: stdCmd(showGossip),
		},
		{
			Name:      "update",
			Usage:     "Update to latest version of the tree, pulls new keys for all followed users",
			Action:    stdCmd(updateTree),
			ArgsUsage: "[optional sequence number to pull to, defaults to latest]",
		},
		{
			Name:      "mail",
			Usage:     "mail a short-lived token to your email that can be used to update your public key",
			Action:    stdCmd(mailToken),
			ArgsUsage: "[email address to send token to]",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "yes",
					Usage: "Bypass confirmation prompts",
				},
			},
		},
		{
			Name:      "upload",
			Usage:     "Upload a public key for a user.",
			Action:    stdCmd(setKey),
			ArgsUsage: "[email address for key] [path to public key, or - for stdin] [token received via email]",
		},
		{
			Name:   "log",
			Usage:  "List updates that have been sent from this client",
			Action: stdCmd(listUpdates),
		},
		{
			Name:      "unfollow",
			Usage:     "Drop user that we were interested in",
			Action:    stdCmd(unfollowUser),
			ArgsUsage: "[at least one email address for user we no longer care about]",
		},
		{
			Name:      "follow",
			Usage:     "Add user that we are interested in",
			Action:    stdCmd(followUser),
			ArgsUsage: "[at least one email address for user we care about]",
		},
		{
			Name:      "history",
			Usage:     "Show history for keys for one or more users",
			Action:    stdCmd(historyForUser),
			ArgsUsage: "[at least one email address for user we care about]",
		},
		{
			Name:      "export",
			Usage:     "Export public key for one or more users",
			Action:    stdCmd(exportUser),
			ArgsUsage: "[at least one email address for user we care about]",
		},
		{
			Name:   "conf",
			Usage:  "Display server configuration",
			Action: stdCmd(showConf),
		},
		{
			Name:   "cache",
			Usage:  "Display cache of data received from server",
			Action: stdCmd(showCache),
		},
		{
			Name:   "list",
			Usage:  "List state of users we care about",
			Action: stdCmd(listUsers),
		},
		{
			Name:   "audit",
			Usage:  "Audit full map",
			Action: stdCmd(audit),
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "yes",
					Usage: "Bypass confirmation prompts",
				},
			},
		},
		{
			Name:   "verify",
			Usage:  "Verify gossip produced by someone else",
			Action: stdCmd(verifyGossip),
		},
	}

	app.Run(os.Args)
}
