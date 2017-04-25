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

package keytransparency

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	"golang.org/x/net/context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/continusec/key-transparency/pb"
)

// HTTPClient talks via HTTP REST to the specified server
type HTTPClient struct {
	BaseURL string
	Client  *http.Client
}

// MapVUFFetchMetadata fetches metadata about the service, ie the public signing key and VUF public key
func (s *HTTPClient) MapVUFFetchMetadata(context.Context, *pb.MapVUFFetchMetadataRequest) (*pb.MapVUFFetchMetadataResponse, error) {
	resp, err := s.Client.Get(s.BaseURL + "/v2/config/serverPublicKey")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err getting public key")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "err getting public key")
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err getting public key")
	}

	resp1, err := s.Client.Get(s.BaseURL + "/v2/config/vufPublicKey")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err getting vuf key")
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "err getting vuf key")
	}

	contents1, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err getting vuf key")
	}

	return &pb.MapVUFFetchMetadataResponse{
		ServerPublicKey: contents,
		VufPublicKey:    contents1,
	}, nil
}

// MapVUFGetValue gets the value for a given key and returns it
func (s *HTTPClient) MapVUFGetValue(ctx context.Context, req *pb.MapVUFGetKeyRequest) (*pb.MapVUFGetKeyResponse, error) {
	resp, err := s.Client.Get(s.BaseURL + "/v2/publicKey/" + string(req.Key) + "/at/" + strconv.Itoa(int(req.TreeSize)))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err getting key")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "err getting key")
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err getting key")
	}

	if err != nil {
		return nil, status.Errorf(codes.Internal, "err getting key")
	}

	var ger pb.MapVUFGetKeyResponse
	err = json.Unmarshal(contents, &ger)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err getting key")
	}

	return &ger, nil
}

// MailToken sends an authorization token to the specified user
func (s *HTTPClient) MailToken(ctx context.Context, req *pb.MailTokenRequest) (*pb.MailTokenResponse, error) {
	resp, err := http.Post(s.BaseURL+"/v2/sendToken/"+req.Email, "", nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, status.Errorf(codes.Internal, "err getting key")
	}

	return &pb.MailTokenResponse{}, nil
}

// MapVUFSetValue sets the value
func (s *HTTPClient) MapVUFSetValue(ctx context.Context, requ *pb.MapVUFSetKeyRequest) (*pb.MapVUFSetKeyResponse, error) {
	req, err := http.NewRequest(http.MethodPut, s.BaseURL+"/v2/publicKey/"+string(requ.Key), bytes.NewReader(requ.Value))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err setting key")
	}
	req.Header.Set("Authorization", requ.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err setting key")
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	default:
		return nil, status.Errorf(codes.Internal, "err setting vuf key")
	}

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err setting vuf key")
	}

	var aer pb.MapVUFSetKeyResponse
	err = json.Unmarshal(contents, &aer)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err setting vuf key")
	}

	return &aer, nil
}
