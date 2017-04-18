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
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/net/context"
)

// sendMail sends a message using SendGrid. Note that this uses an older revision of the
// sendgrid-go mail client, specifically revision d88aa4dd8b2a9df3a9693d35d4d0f686b3bcff9a
// at time of writing. Newer versions are not currently compatible with Google App Engine.
func sendMail(ctx context.Context, sender string, recipients []string, subject, body string) error {
	for _, recip := range recipients {

		m := mail.NewV3MailInit(mail.NewEmail(sender, sender), subject, mail.NewEmail(recip, recip), mail.NewContent("text/plain", body))

		request := sendgrid.GetRequest(config.SendGrid.SecretKey, "/v3/mail/send", "https://api.sendgrid.com")
		request.Method = "POST"
		request.Body = mail.GetRequestBody(m)
		_, err := sendgrid.API(request)
		if err != nil {
			return err
		}
	}
	return nil
}
