package main

import (
	"os"
	"time"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()

	app.Name = "cks"
	app.Usage = "utility for interaction with the Continusec Key Server"
	app.Version = "v0.1"
	app.Compiled = time.Now()
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Adam Eijdenberg",
			Email: "adam@continusec.com",
		},
	}
	app.Copyright = "(c) 2016 Continusec Pty Ltd"

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
			Name:      "pull",
			Usage:     "Update to latest version of the tree",
			Action:    stdCmd(updateTree),
			ArgsUsage: "[optional sequence number to pull to, defaults to latest]",
		},
		{
			Name:      "token",
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
			Name:      "push",
			Usage:     "Upload a public key for a user.",
			Action:    stdCmd(setKey),
			ArgsUsage: "[email address for key] [path to public key, or - for stdin] [token received via email]",
		},
		{
			Name:      "log",
			Usage:     "List updates that have been sent from this client",
			Action:    stdCmd(listUpdates),
			ArgsUsage: "[email address to list updates for, or no args for all]",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "check",
					Usage: "Check for sequence numbers for any unsequenced against current head.",
				},
			},
		},
		{
			Name:      "follow",
			Usage:     "Add user that we are interested in",
			Action:    stdCmd(followUser),
			ArgsUsage: "[email address for user we care about]",
		},
		{
			Name:   "list",
			Usage:  "List state of users we care about",
			Action: stdCmd(listUsers),
		},
		{
			Name:      "unfollow",
			Usage:     "Drop user that we were interested in",
			Action:    stdCmd(unfollowUser),
			ArgsUsage: "[email address for user we no longer care about]",
		},
		{
			Name:   "audit",
			Usage:  "Audit full map",
			Action: stdCmd(audit),
		},
	}

	app.Run(os.Args)
}
