/*
   Copyright 2016 Continusec Pty Ltd

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
	"fmt"

	"golang.org/x/net/context"
)

// sendMail should send an email, this is a stub for now. PR welcome for integration with a good mail API
func sendMail(ctx context.Context, sender string, recipients []string, subject, body string) error {
	fmt.Printf("================================================\n")
	fmt.Printf("         Email that should be sent\n")
	fmt.Printf("================================================\n")
	fmt.Printf("Subject: %s\n", subject)
	fmt.Printf("From: %s\n", sender)
	for _, r := range recipients {
		fmt.Printf("To: %s\n", r)
	}
	fmt.Printf("\n%s\n", body)
	fmt.Printf("================================================\n")
	return nil
}
