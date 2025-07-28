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
	"net/http"

	normallog "log"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	gaelog "google.golang.org/appengine/log"
)

// Returns a context object
func getContext(request *http.Request) context.Context {
	if config.Server.HostedInGAE {
		return appengine.NewContext(request)
	} else {
		return context.Background()
	}
}

// Log an error somewhere
func logError(ctx context.Context, m string) {
	if config.Server.HostedInGAE {
		gaelog.Errorf(ctx, m)
	} else {
		normallog.Println(m)
	}
}
