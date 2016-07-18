package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

var db *bolt.DB

// AddEntryResult is the data returned when setting a key in the map
type AddEntryResult struct {
	// MutationEntryLeafHash is the leaf hash of the entry added to the mutation log for the map.
	// Once this has been verified to be added to the mutation log for the map, then this entry
	// will be reflected for the map at that size (provided no conflicting operation occurred).
	MutationEntryLeafHash []byte `json:"mutationEntryLeafHash"`
}

func confirmIt(prompt string) bool {
	for {
		fmt.Printf("%s Type yes or no to continue: ", prompt)

		var resp string
		_, err := fmt.Scanln(&resp)
		if err == io.EOF {
			return false
		}

		resp = strings.ToLower(strings.TrimSpace(resp))
		switch {
		case strings.HasPrefix(resp, "yes"):
			return true
		case strings.HasPrefix(resp, "no"):
			return false
		}
	}

}

type UpdateResult struct {
	// Email address that this was added for
	Email string

	// Mutation log entry as returned by the server
	MutationLeafHash []byte

	// sha256 of the value set
	ValueHash []byte

	// -1 means unknown
	LeafIndex int64

	// Timestamp when written
	Timestamp time.Time
}

func listUpdates(c *cli.Context) error {
	var emailAddress string

	switch c.NArg() {
	case 0:
		// ignore
	case 1:
		emailAddress = c.Args().Get(0)
	default:
		return cli.NewExitError("incorrect number of arguments. see help", 1)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Email", "Value Hash", "Timestamp", "Mutation Log Entry", "Sequence"})

	gotOne := func(v []byte) error {
		var ur UpdateResult
		err := gob.NewDecoder(bytes.NewReader(v)).Decode(&ur)
		if err != nil {
			return err
		}

		table.Append([]string{
			ur.Email,
			base64.StdEncoding.EncodeToString(ur.ValueHash),
			ur.Timestamp.String()[:19],
			base64.StdEncoding.EncodeToString(ur.MutationLeafHash),
			strconv.Itoa(int(ur.LeafIndex)),
		})

		return nil
	}

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("updates"))
		if len(emailAddress) == 0 {
			b.ForEach(func(k, v []byte) error { return gotOne(v) })
		} else {
			eh := sha256.Sum256([]byte(emailAddress))
			c := b.Cursor()
			k, v := c.Seek(eh[:])
			for k != nil {
				if !bytes.Equal(eh[:], k[:len(eh)]) {
					return nil
				}
				err := gotOne(v)
				if err != nil {
					return err
				}
				k, v = c.Next()
			}
		}

		return nil
	})
	if err != nil {
		return cli.NewExitError("error writing result to local DB: "+err.Error(), 5)
	}

	table.Render()

	return nil
}

func setKey(c *cli.Context) error {
	if c.NArg() != 3 {
		return cli.NewExitError("incorrect number of arguments. see help", 1)
	}
	emailAddress := c.Args().Get(0)
	publicKeyPath := c.Args().Get(1)
	token := c.Args().Get(2)

	if strings.Index(emailAddress, "@") == -1 {
		return cli.NewExitError("email address not recognized", 4)
	}

	var pubKeyBytes []byte
	if publicKeyPath == "-" {
		var err error
		fmt.Println("Starting read...")
		pubKeyBytes, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return cli.NewExitError("error reading public key: "+err.Error(), 3)
		}
		fmt.Println("Read complete.")
	} else {
		var err error
		pubKeyBytes, err = ioutil.ReadFile(publicKeyPath)
		if err != nil {
			return cli.NewExitError("error reading public key: "+err.Error(), 2)
		}
	}

	fmt.Printf("Setting key for %s with token...\n", emailAddress)

	url := c.GlobalString("server") + "/v1/publicKey/" + emailAddress

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(pubKeyBytes))
	if err != nil {
		return cli.NewExitError("error building HTTP request: "+err.Error(), 2)
	}
	req.Header.Set("Authorization", token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return cli.NewExitError("error making HTTP request: "+err.Error(), 2)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return cli.NewExitError("non-200 response received", resp.StatusCode)
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return cli.NewExitError("error making HTTP request: "+err.Error(), 3)
	}

	var aer AddEntryResult
	err = json.Unmarshal(contents, &aer)
	if err != nil {
		return cli.NewExitError("error making HTTP request: "+err.Error(), 4)
	}

	fmt.Printf("Success. Leaf hash of mutation: %s\n", base64.StdEncoding.EncodeToString(aer.MutationEntryLeafHash))

	k1 := sha256.Sum256([]byte(emailAddress))

	// second part of key is a timestamp for sorting, does not need to match
	// any timestamp inside of the value
	k2 := make([]byte, 8)
	binary.BigEndian.PutUint64(k2, uint64(time.Now().UnixNano()))

	key := append(k1[:], k2...)

	buffer := &bytes.Buffer{}
	vh := sha256.Sum256(pubKeyBytes)
	err = gob.NewEncoder(buffer).Encode(&UpdateResult{
		Email:            emailAddress,
		MutationLeafHash: aer.MutationEntryLeafHash,
		ValueHash:        vh[:],
		LeafIndex:        -1,
		Timestamp:        time.Now(),
	})
	if err != nil {
		return cli.NewExitError("error writing result to local DB: "+err.Error(), 6)
	}

	value := buffer.Bytes()

	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("updates"))
		err := b.Put(key, value)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return cli.NewExitError("error writing result to local DB: "+err.Error(), 5)
	}

	return nil
}

func mailToken(c *cli.Context) error {
	if c.NArg() != 1 {
		return cli.NewExitError("exactly one email address must be specified", 1)
	}
	emailAddress := c.Args().Get(0)

	if strings.Index(emailAddress, "@") == -1 {
		return cli.NewExitError("email address not recognized", 4)
	}

	if !c.GlobalBool("yes") {
		if !confirmIt(fmt.Sprintf("Are you sure you want to generate and send a token to address (%s)? Please only do so if you own that email account.", emailAddress)) {
			return cli.NewExitError("user cancelled request", 3)
		}
	}

	fmt.Printf("Sending mail to %s with token...\n", emailAddress)

	url := c.GlobalString("server") + "/v1/sendToken/" + emailAddress

	resp, err := http.Post(url, "", nil)
	if err != nil {
		return cli.NewExitError("error making HTTP request: "+err.Error(), 2)
	}

	if resp.StatusCode != 200 {
		return cli.NewExitError("non-200 response received", resp.StatusCode)
	}

	fmt.Printf("Success. See email for further instructions.\n")

	return nil
}

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

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "server",
			Value: "https://continusec-key-server.appspot.com",
			Usage: "API endpoint to use (leave default unless developing your own)",
		},
		cli.BoolFlag{
			Name:  "yes",
			Usage: "Bypass confirmation prompts",
		},
	}

	app.Commands = []cli.Command{
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
			Name:      "listupdates",
			Usage:     "List updates that have been sent from this client",
			Action:    listUpdates,
			ArgsUsage: "[email address to list updates for, or no args for all]",
		},
	}

	u, err := user.Current()
	if err != nil {
		fmt.Printf("Error finding DB: %+v\n", err)
		os.Exit(1)
	}

	dbPath := filepath.Join(u.HomeDir, ".cksdb")

	fmt.Println("Pre-open db...")
	db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		fmt.Printf("Error opening DB: %+v\n", err)
		os.Exit(2)
	}
	defer db.Close()
	fmt.Println("Database opened.")

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("updates"))
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error initializing DB: %+v\n", err)
		os.Exit(2)
	}

	fmt.Println("Init complete.")

	app.Run(os.Args)
}
