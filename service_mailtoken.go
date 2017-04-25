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
	"html/template"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/continusec/key-transparency/pb"

	"golang.org/x/net/context"
)

var tokenTemplate = template.Must(template.New("token").Parse(`Thank you for requesting an authorization token for submitting your key data.

The following token has been generated and is valid for 1 hour:
{{ .Token }}

Example usage (to export your GPG public key):

gpg --export {{ .Email }} | curl -H "Authorization: {{ .Token }}" -i -X PUT {{ .BasePath }}/v2/publicKey/{{ .Email }} -d @-

Or, using the cks tool:

gpg --export {{ .Email }} | cks upload {{ .Email }} - {{ .Token }}

If you didn't make this request, then please ignore this message.
`))

// MailToken sends an authorization token to the specified user
func (s *LocalService) MailToken(ctx context.Context, req *pb.MailTokenRequest) (*pb.MailTokenResponse, error) {
	// Get the username
	token, err := makeToken(s.MailTokenKey, req.Email, time.Now().Add(time.Hour))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error creating token: %s", err)
	}

	buf := &bytes.Buffer{}
	err = tokenTemplate.Execute(buf, map[string]string{
		"Email":    req.Email,
		"Token":    base64.StdEncoding.EncodeToString(token),
		"BasePath": s.BaseURL,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "error executing template: %s", err)
	}

	err = s.Mailer.SendMessage(ctx, req.Email, string(buf.Bytes()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "extra sending token: %s", err)
	}

	return &pb.MailTokenResponse{}, nil
}
