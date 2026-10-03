package main

import (
	"crypto/tls"
	"net/http"
)

var client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
