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
	"encoding/base64"
	"encoding/json"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/continusec/key-transparency/pb"

	"github.com/continusec/verifiabledatastructures"
	vpb "github.com/continusec/verifiabledatastructures/pb"
	"golang.org/x/net/context"
)

// MapVUFSetValue sets the value
func (s *LocalService) MapVUFSetValue(ctx context.Context, req *pb.MapVUFSetKeyRequest) (*pb.MapVUFSetKeyResponse, error) {
	// Check if we have a valid token
	token, err := base64.StdEncoding.DecodeString(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "err base64 decoding")
	}
	err = validateToken(&s.MailTokenKey.PublicKey, string(req.Key), token)
	if err != nil { // no good, fail
		return nil, status.Errorf(codes.PermissionDenied, "err validating token")
	}

	// Apply the vuf to the username
	vufResult, err := applyVUF(s.VUFKey, req.Key)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err vuffing")
	}

	// Read the body, this should be DER encoded PGP Public Key - bytes, not PEM.
	// Validate the input
	err = validateData(req.Value)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "err validating data: %s", err)
	}

	// Load up the Map
	// Next sequence
	nextSequence := int64(0) // unless advised otherwise

	// Get key for VUF
	keyForVuf := getKeyForVUF(vufResult)

	// Get the current value so that we can pick the next sequence
	curVal, err := s.Keys.Get(ctx, keyForVuf, verifiabledatastructures.Head)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err looking up previous key")
	}

	// Get the previous hash, since we'll need soon
	prevHash := verifiabledatastructures.LeafMerkleTreeHash(curVal.Value.LeafInput)

	// If the prev hash IS NOT empty (if it is, we already like the default val of 0)
	if !bytes.Equal(emptyLeafHash[:], prevHash) {
		// If we managed to get the value, then let's decode:
		shedBytes, err := verifiabledatastructures.ShedRedactedJSONFields(curVal.Value.ExtraData)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "err reading previous value")
		}

		var pkd pb.VersionedKeyData
		err = json.Unmarshal(shedBytes, &pkd)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "err marshalling new value")
		}

		if bytes.Equal(pkd.Value, req.Value) {
			return nil, nil // no action required
		}

		nextSequence = pkd.Sequence + 1
	}

	// Construct new data
	jb, err := json.Marshal(&pb.VersionedKeyData{
		Sequence:      nextSequence,
		Key:           req.Key,
		Value:         req.Value,
		PriorTreeSize: curVal.TreeSize,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err marshalling new value")
	}

	// Update the value - will only apply if no-one else modifies.
	v, err := verifiabledatastructures.CreateRedactableJSONLeafData(jb)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err creating new value")
	}
	aer, err := s.Keys.Update(ctx, keyForVuf, v, prevHash)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err updating new value")
	}

	return &pb.MapVUFSetKeyResponse{MapResponse: &vpb.MapSetValueResponse{
		LeafHash: aer.LeafHash(),
	}}, nil
}
