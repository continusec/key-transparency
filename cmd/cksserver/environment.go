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
	"net/http"
	"time"

	normallog "log"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	gaelog "google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
)

// Returns a context object
func getContext(request *http.Request) context.Context {
	if config.Server.HostedInGAE {
		return appengine.NewContext(request)
	} else {
		return context.Background()
	}
}

// Return an HttpClient with a decent timeout
func getHttpClient(ctx context.Context) *http.Client {
	if config.Server.HostedInGAE {
		// The default HttpClient on Google App Engine appears to have a 5 second timeout,
		// this creates a client with a longer timeout.
		cctx, _ := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
		return urlfetch.Client(cctx)
	} else {
		// Default client is good enough
		return http.DefaultClient
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
