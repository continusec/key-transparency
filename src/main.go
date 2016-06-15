/* Copyright (C) 2016 Continusec Pty Ltd - All Rights Reserved */

package main

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() {
	r := mux.NewRouter()

	http.Handle("/", r)
}
