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

// This file contains routines for loading configuration data into global
// variables that are available to the rest of the app.

package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"html/template"
	"strings"

	"github.com/BurntSushi/toml"
)

// Datastructure for the "config.toml" file
type tomlConfig struct {
	Server     serverConf
	Continusec continusecConf
	SendGrid   sendgridConf
	Crypto     privateKeyConf
}

type serverConf struct {
	// The BasePath of the server - used for insertion into email templates
	BasePath string `toml:"base_path"`

	// If set to true, will disable requiring a token when accepting a new public
	// key for a user, meaning you don't need to email a token first. This can
	// be useful during testing or bulk import on a private server
	DisableAuthentication bool `toml:"disable_authentication"`
}

type continusecConf struct {
	// The Continusec account to use - usually a number. Create a new Continusec
	// account at: https://www.continusec.com/
	Account string

	// Which Verifiable Map to use - you need to create an empty Map in the Continusec
	// console before use.
	Map string

	// This key is created in the Continusec user interface and must have permission
	// to read all redacted fields, as well as Get/Set/Delete map values.
	MutatingKey string `toml:"mutating_key"`

	// This key is created in the Continusec user interface and must have permission to:
	// - Get value / inclusion proof for map keys
	// - Read map mutation log entries
	// - Read map mutation log tree hashes, and map tree head log entries and hashes
	// The "Redacted Fields Allowed" setting must be:
	// sequence,action,key,value,previous,timestamp,mutation_log/*,map_hash
	// (this prevents users from listing all email addresses contained by the map)
	LimitedReadOnlyKey string `toml:"readonly_key"`
}

type sendgridConf struct {
	// Secret Key to allow sending mail via SendGrid.
	// Note that if you set DisableAuthentication to true above, then
	// it's fine to leave this blank, and no email will be sent.
	SecretKey string `toml:"secret_key"`

	// The from address used for messages sent
	FromAddress string `toml:"from_address"`

	// The subject used for outgoing emails
	EmailSubject string `toml:"mail_subject"`

	// The email template used for token emails. It is given BasePath, Email and Token
	// as input.
	TokenTemplate string `toml:"token_template"`
}

type privateKeyConf struct {
	// Private key (EC PEM) to use for signing responses from the server
	ServerPrivateECKey string `toml:"server_ec_private_key"`

	// Private key (EC PEM) to use for signing tokens for verifying email
	// address ownership. Can be left blank if DisableAuthentication set above.
	EmailTokenPrivateECKey string `toml:"email_token_ec_private_key"`

	// Private key (RSA PEM) to use for mapping email address to a map key in order
	// to provide privacy against directory harvest attacks.
	VufPrivateRsaKey string `toml:"vuf_rsa_private_key"`
}

var (
	// Config holding all of the above
	config tomlConfig

	// Parsed email template
	emailTemplate *template.Template

	// Parse private keys
	emailTokenPrivateKey *ecdsa.PrivateKey
	serverPrivateKey     *ecdsa.PrivateKey
	vufPrivateKey        *rsa.PrivateKey

	// Serialized public keys (DER) ready to serve
	serverPublicKeyBytes []byte
	vufPublicKeyBytes    []byte
)

// readRSAPrivateKeyFromPEM converts a string that should be a PEM of type "PRIVATE KEY" to an
// actual RSA private key.
func readRSAPrivateKeyFromPEM(s string) (*rsa.PrivateKey, error) {
	var p *pem.Block
	p, _ = pem.Decode([]byte(s))
	if p == nil {
		return nil, ErrInvalidKey
	}

	if !strings.HasSuffix(p.Type, "PRIVATE KEY") {
		return nil, ErrInvalidKey
	}

	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	rv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKey
	}

	return rv, nil
}

// readECPrivateKeyFromPEM converts a string that should be a PEM of type "EC PRIVATE KEY" to an
// actual RSA private key.
func readECPrivateKeyFromPEM(s string) (*ecdsa.PrivateKey, error) {
	var p *pem.Block
	p, _ = pem.Decode([]byte(s))
	if p == nil {
		return nil, ErrInvalidKey
	}

	if !strings.HasSuffix(p.Type, "EC PRIVATE KEY") {
		return nil, ErrInvalidKey
	}

	key, err := x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Parse the private keys contained in an already loaded configuration,
// and also serialize out any public keys we'll be serving later.
func initPrivateKeys() error {
	var err error

	emailTokenPrivateKey, err = readECPrivateKeyFromPEM(config.Crypto.EmailTokenPrivateECKey)
	if err != nil {
		return err
	}

	serverPrivateKey, err = readECPrivateKeyFromPEM(config.Crypto.ServerPrivateECKey)
	if err != nil {
		return err
	}

	vufPrivateKey, err = readRSAPrivateKeyFromPEM(config.Crypto.VufPrivateRsaKey)
	if err != nil {
		return err
	}

	serverPublicKeyBytes, err = x509.MarshalPKIXPublicKey(&serverPrivateKey.PublicKey)
	if err != nil {
		return err
	}

	vufPublicKeyBytes, err = x509.MarshalPKIXPublicKey(&vufPrivateKey.PublicKey)
	if err != nil {
		return err
	}

	return nil
}

// Parse any message tempaltes in an already loaded configuration.
func initMessageTemplates() error {
	var err error

	emailTemplate, err = template.New("master").Parse(config.SendGrid.TokenTemplate)
	if err != nil {
		return err
	}

	return nil
}

// Load the "config.toml" file and call other initializers.
func loadConfigFile() error {
	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		return err
	}

	err = initPrivateKeys()
	if err != nil {
		return err
	}

	err = initMessageTemplates()
	if err != nil {
		return err
	}

	return err
}
