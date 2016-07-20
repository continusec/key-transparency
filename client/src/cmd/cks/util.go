package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/continusec/go-client/continusec"
	"github.com/urfave/cli"
)

// A Sig is the asn1 form of this.
type ECDSASignature struct {
	// R, S are as returned by ecdsa.Sign
	R, S *big.Int
}

var (
	ErrWrongKeyFormat   = errors.New("ErrWrongKeyFormat")
	ErrCouldNotVerify   = errors.New("ErrCouldNotVerify")
	ErrShouldNotGetHere = errors.New("ErrShouldNotGetHere")
	ErrServerError      = errors.New("ErrServerError")
)

type CachingVerifyingRT struct {
	DB *bolt.DB
}

type CacheEntry struct {
	Timestamp time.Time
	Signature []byte
	Data      []byte
}

func (self *CachingVerifyingRT) getRespFromCache(key string) *http.Response {
	var entry CacheEntry
	err := self.DB.View(func(tx *bolt.Tx) error {
		return gob.NewDecoder(bytes.NewBuffer(tx.Bucket([]byte("cache")).Get([]byte(key)))).Decode(&entry)
	})
	if err != nil {
		return nil
	}
	return &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(bytes.NewReader(entry.Data)),
	}
}

// Only does GETs. Special cases certain GETS, like to /tree/0
func (self *CachingVerifyingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		return nil, ErrShouldNotGetHere
	}

	key := r.URL.String()

	// First try cache, maybe
	switch {
	case strings.HasSuffix(key, "/v1/wrappedMap/log/treehead/tree/0"):
		// no cache
	case strings.HasSuffix(key, "/v1/wrappedMap/tree/0"):
		// no cache
	default: // cache!
		r2 := self.getRespFromCache(key)
		if r2 != nil {
			return r2, nil
		}
	}

	// Otherwise, go out and fetch
	fmt.Printf("Fetching: %s\n", key)

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, ErrServerError
	}

	// Now attempt to cache
	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(resp.Header.Get("x-body-signature"))
	if err != nil {
		return nil, err
	}

	// First, check sig - even for bootstrap case (of fetching key)
	var pubKey []byte
	if strings.HasSuffix(key, "/v1/config/serverPublicKey") {
		pubKey = contents
	} else {
		err = self.DB.View(func(tx *bolt.Tx) error {
			pubKey = tx.Bucket([]byte("conf")).Get([]byte("serverKey"))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// Regardless, do the check
	err = verifySignedData(contents, sig, pubKey)
	if err != nil {
		return nil, err
	}

	// Do we need to massage the key a little?
	switch {
	case strings.HasSuffix(key, "/v1/wrappedMap/log/treehead/tree/0"):
		x := make(map[string]interface{})
		err = json.Unmarshal(contents, &x)
		if err != nil {
			return nil, err
		}
		ts, ok := x["tree_size"].(float64)
		if !ok {
			return nil, ErrWrongKeyFormat
		}

		key = key[:strings.LastIndex(key, "/")+1] + strconv.Itoa(int(ts))
	case strings.HasSuffix(key, "/v1/wrappedMap/tree/0"):
		x := make(map[string]interface{})
		err = json.Unmarshal(contents, &x)
		if err != nil {
			return nil, err
		}
		xxx, ok := x["mutation_log"].(map[string]interface{})
		if !ok {
			return nil, ErrWrongKeyFormat
		}

		ts, ok := xxx["tree_size"].(float64)
		if !ok {
			return nil, ErrWrongKeyFormat
		}

		key = key[:strings.LastIndex(key, "/")+1] + strconv.Itoa(int(ts))
	}

	// now see if massaged key is in cache, and if so, return that value:
	r1 := self.getRespFromCache(key)
	if r1 != nil {
		return r1, nil
	}

	// else put in cache
	buf := &bytes.Buffer{}
	err = gob.NewEncoder(buf).Encode(&CacheEntry{
		Timestamp: time.Now(),
		Signature: sig,
		Data:      contents,
	})
	if err != nil {
		return nil, err
	}

	err = self.DB.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("cache")).Put([]byte(key), buf.Bytes())
	})
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode: 200,
		Body:       ioutil.NopCloser(bytes.NewReader(contents)),
	}, nil

}

func getMap() (*continusec.VerifiableMap, error) {
	db, err := GetDB()
	if err != nil {
		return nil, err
	}
	var server string
	err = db.View(func(tx *bolt.Tx) error {
		server = string(tx.Bucket([]byte("conf")).Get([]byte("server")))
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &continusec.VerifiableMap{Client: continusec.DefaultClient.WithBaseUrl(server + "/v1/wrappedMap").WithHttpClient(&http.Client{Transport: &CachingVerifyingRT{DB: db}})}, nil
}

func doGet(url string) ([]byte, error) {
	db, err := GetDB()
	if err != nil {
		return nil, err
	}

	resp, err := (&http.Client{Transport: &CachingVerifyingRT{DB: db}}).Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, ErrBadReturnVal
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return contents, nil
}

// No side-effect
func verifySignedData(data, sig, pub []byte) error {
	hashed := sha256.Sum256(data)

	var s ECDSASignature
	_, err := asn1.Unmarshal(sig, &s)
	if err != nil {
		return err
	}

	pkey, err := x509.ParsePKIXPublicKey(pub)
	if err != nil {
		return err
	}

	ppkey, ok := pkey.(*ecdsa.PublicKey)
	if !ok {
		return ErrWrongKeyFormat
	}

	if !ecdsa.Verify(ppkey, hashed[:], s.R, s.S) {
		return ErrCouldNotVerify
	}

	return nil
}

// Return wrapped CLI exit error
func handleError(err error) error {
	return cli.NewExitError("Error: "+err.Error(), 1)
}

// Return true if user types "yes"
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

// Use GetDB / InitDB below
var ourDB *bolt.DB

// Get the current database, returning error if unavailable, caching if there
func GetDB() (*bolt.DB, error) {
	if ourDB == nil {
		var err error
		ourDB, err = openDB(true, false)
		if err != nil {
			fmt.Println("Error opening database. If this is your first time running the tool, run `cks init` to initialize the local database.")
			return nil, err
		}
	}
	return ourDB, nil
}

// Delete any existing db, create a new one
func InitDB(server string) (*bolt.DB, error) {
	var err error
	ourDB, err = openDB(false, true)
	if err != nil {
		return nil, err
	}

	err = ourDB.Update(func(tx *bolt.Tx) error {
		conf, err := tx.CreateBucket([]byte("conf"))
		if err != nil {
			return err
		}

		err = conf.Put([]byte("server"), []byte(server))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucket([]byte("mapstate"))
		if err != nil {
			return err
		}

		_, err = tx.CreateBucket([]byte("cache"))
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return ourDB, nil
}

// Used by GetDB / InitDB
func openDB(failIfNotThere, deleteExisting bool) (*bolt.DB, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join(u.HomeDir, ".cksdb")

	if failIfNotThere {
		_, err := os.Stat(dbPath)
		if err != nil { // probabably doesn't exist
			return nil, err
		}
	}

	if deleteExisting {
		err = os.Remove(dbPath)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		}
	}

	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}

	return db, nil
}
