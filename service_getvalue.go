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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/continusec/key-transparency/pb"

	"golang.org/x/net/context"
)

// MapVUFGetValue gets the value for a given key and returns it
func (s *LocalService) MapVUFGetValue(ctx context.Context, req *pb.MapVUFGetKeyRequest) (*pb.MapVUFGetKeyResponse, error) {
	// Get the username
	// Apply the vuf to the username
	vufResult, err := applyVUF(s.VUFKey, req.Key)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err vuffing")
	}

	// Load up the Map
	// Get the current value
	curVal, err := s.Keys.Get(ctx, getKeyForVUF(vufResult), req.TreeSize)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err looking up value")
	}

	// Get the public key data response
	// Formulate our response object
	return &pb.MapVUFGetKeyResponse{
		MapResponse: curVal,
		VufResult:   vufResult,
	}, nil
}
