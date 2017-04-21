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
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/boltdb/bolt"
	"github.com/continusec/verifiabledatastructures/pb"
)

// Given a database with a cache bucket, use this to implement a RoundTripper that
// 1. caches nearly all GETs
// 2. verifies successful responses
type CachingVerifyingRT struct {
	DB *bolt.DB
}

// Value in cache is gob of this
type CacheEntry struct {
	// When we cached it
	Timestamp time.Time

	// The signature received from the server
	Signature []byte

	// The data receiving from the server
	Data []byte

	// URL of the resource, not saved in the entry though
	url string
}

// Fetch from the cache
func (self *CachingVerifyingRT) getValFromCache(key string) (*CacheEntry, error) {
	var entry CacheEntry
	err := self.DB.View(func(tx *bolt.Tx) error {
		return gob.NewDecoder(bytes.NewBuffer(tx.Bucket([]byte("cache")).Get([]byte(key)))).Decode(&entry)
	})
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// Fetch but faked out as a real response object
func (self *CachingVerifyingRT) getRespFromCache(key string) *http.Response {
	entry, err := self.getValFromCache(key)
	if err == nil {
		return &http.Response{
			StatusCode: 200,
			Body:       ioutil.NopCloser(bytes.NewReader(entry.Data)),
		}
	}
	return nil
}

// Only does GETs. Special cases certain GETS, like /tree/0 which it won't cache.
// See code for detailed special cases
func (self *CachingVerifyingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet {
		return nil, errors.New("Unexpected request - non-GET from cache")
	}

	key := r.URL.String()

	// First see if it's a special case, and if not try cache
	switch {
	case strings.HasSuffix(key, "/v2/account/0/map/keys/log/mutation/tree/0"):
		// no cache
	case strings.HasSuffix(key, "/v2/account/0/map/keys/log/treehead/tree/0"):
		// no cache
	case strings.HasSuffix(key, "/v2/account/0/map/keys/tree/0"):
		// no cache
	default: // cache!
		r2 := self.getRespFromCache(key)
		if r2 != nil {
			return r2, nil
		}
	}

	// Otherwise, go out and fetch
	fmt.Fprintf(os.Stderr, "Fetching: %s\n", key)

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("Received non-200 response from server: %d", resp.StatusCode))
	}

	// Now attempt to cache
	defer resp.Body.Close()

	// Read raw content
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Get the signature
	sig, err := base64.StdEncoding.DecodeString(resp.Header.Get("x-body-signature"))
	if err != nil {
		return nil, err
	}

	// First, check sig - even for bootstrap case (of fetching key)
	var pubKey []byte
	if strings.HasSuffix(key, "/v2/config/serverPublicKey") {
		pubKey = contents
	} else {
		pubKey, err = getPubKey(self.DB)
		if err != nil {
			return nil, err
		}
	}

	// Regardless, do the check
	err = verifySignedData(contents, sig, pubKey)
	if err != nil {
		return nil, errors.New("Unable to verify the signature of the response from the server: " + err.Error())
	}

	var actSize int64

	// For requests that were for the latest version of something, look into the response
	// to find what the answer was, and thus cache that for future requests.
	switch {
	case strings.HasSuffix(key, "/v2/account/0/map/keys/log/mutation/tree/0"):
		var lth *pb.LogTreeHashResponse
		err = json.Unmarshal(contents, &lth)
		if err != nil {
			return nil, err
		}
		if lth != nil {
			actSize = lth.TreeSize
		}
		key = key[:strings.LastIndex(key, "/")+1] + strconv.Itoa(int(actSize))
	case strings.HasSuffix(key, "/v2/account/0/map/keys/log/treehead/tree/0"):
		var lth *pb.LogTreeHashResponse
		err = json.Unmarshal(contents, &lth)
		if err != nil {
			return nil, err
		}
		if lth != nil {
			actSize = lth.TreeSize
		}
		key = key[:strings.LastIndex(key, "/")+1] + strconv.Itoa(int(actSize))
	case strings.HasSuffix(key, "/v2/account/0/map/keys/tree/0"):
		var lth *pb.MapTreeHashResponse
		err = json.Unmarshal(contents, &lth)
		if err != nil {
			return nil, err
		}
		if lth != nil && lth.MutationLog != nil {
			actSize = lth.MutationLog.TreeSize
		}
		key = key[:strings.LastIndex(key, "/")+1] + strconv.Itoa(int(actSize))
	}

	// Now see if massaged key is in cache, and if so, return that value, ie if we
	// already had a value for the tree head, return that rather than whatever new we
	// received, because it should not have changed, and changing it might make a
	// verification error write over the evidence.
	r1 := self.getRespFromCache(key)
	if r1 != nil {
		return r1, nil
	}

	// Finally, store in the cache
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

// Get the database, make the request, and deal with it.
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
		return nil, errors.New(fmt.Sprintf("Unexpected non-200 result from server: %d", resp.StatusCode))
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return contents, nil
}
