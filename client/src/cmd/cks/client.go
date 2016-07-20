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
			Action: showConf,
		},
		{
			Name:   "cache",
			Usage:  "Display cache of data received from server",
			Action: showCache,
		},
		{
			Name:   "update",
			Usage:  "Update to latest version of the tree",
			Action: updateTree,
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:  "sequence",
					Usage: "Update to a particular sequence number",
				},
			},
		},

		{
			Name:      "follow",
			Usage:     "Add user that we are interested in",
			Action:    followUser,
			ArgsUsage: "[email address for user we care about]",
		},
		{
			Name:   "list",
			Usage:  "List state of users we care about",
			Action: listUsers,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "check",
					Usage: "Check for new keys",
				},
			},
		},
		{
			Name:      "unfollow",
			Usage:     "Drop user that we were interested in",
			Action:    unfollowUser,
			ArgsUsage: "[email address for user we no longer care about]",
		},
		{
			Name:      "mailtoken",
			Usage:     "mail a short-lived token to your email that can be used to update your public key",
			Action:    mailToken,
			ArgsUsage: "[email address to send token to]",
		},
		{
			Name:      "setkey",
			Usage:     "Update public key for a user.",
			Action:    setKey,
			ArgsUsage: "[email address for key] [path to public key, or - for stdin] [token received via email]",
		},
		{
			Name:      "listmyupdates",
			Usage:     "List updates that have been sent from this client",
			Action:    listUpdates,
			ArgsUsage: "[email address to list updates for, or no args for all]",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "check",
					Usage: "Check for sequence numbers for any unsequenced against current head.",
				},
			},
		},
	}

	app.Run(os.Args)
}
