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
	"crypto/x509"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/continusec/key-transparency/pb"

	"golang.org/x/net/context"
)

// MapVUFFetchMetadata fetches metadata about the service, ie the public signing key and VUF public key
func (s *LocalService) MapVUFFetchMetadata(context.Context, *pb.MapVUFFetchMetadataRequest) (*pb.MapVUFFetchMetadataResponse, error) {
	b, err := x509.MarshalPKIXPublicKey(&s.VUFKey.PublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err marshalling bytes")
	}
	b2, err := x509.MarshalPKIXPublicKey(s.ServerPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "err marshalling bytes")
	}
	return &pb.MapVUFFetchMetadataResponse{
		VufPublicKey:    b,
		ServerPublicKey: b2,
	}, nil
}
