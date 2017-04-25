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
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/net/context"
)

// SendGridMailer sends mail using the SendGrid API
type SendGridMailer struct {
	Subject   string
	From      string
	SecretKey string
}

// SendMessage sends the message
func (s *SendGridMailer) SendMessage(ctx context.Context, recipient, message string) error {
	m := mail.NewV3MailInit(mail.NewEmail(s.From, s.From), s.Subject, mail.NewEmail(recipient, recipient), mail.NewContent("text/plain", message))
	request := sendgrid.GetRequest(s.SecretKey, "/v3/mail/send", "https://api.sendgrid.com")
	request.Method = "POST"
	request.Body = mail.GetRequestBody(m)
	_, err := sendgrid.API(request)
	if err != nil {
		return err
	}
	return nil
}
