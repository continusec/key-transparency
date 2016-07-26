# Continusec Key Server

This project contains the source code for a [CONIKS](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-melara.pdf)-inspired Key Transparency server that provides an effective demonstration of how to use the [Continusec Verifiable Data Structures API](https://www.continusec.com/) to produce a trustworthy service.

A running version of this code can be found at:

[https://continusec-key-server.appspot.com/](https://continusec-key-server.appspot.com/)

And the [corresponding client](https://github.com/continusec/key-transparency/tree/master/client) can be used to access it in a more useful fashion.

The intention of releasing this source is to show an end-to-end example of how a Verifiable Map can be used.


## Pre-requisites

If you want to run your own instance of a Continusec Key Server, please begin by [creating an account at Continusec](https://console.continusec.com/).

### Configuring Continusec

Once you have a Continusec account:

1. Take note of the account number assigned by Continusec.
2. Create a new Verifiable Map object and take note of the name.
3. Create a first access rule with:
	- a generated API key (take note of this for later)
	- no log permissions
	- The following map permissions:
	   - Set / delete map values
	   - Get value / inclusion proof for map keys
   - no account permissions
   - `Logs / maps permitted` set to name of the map created earlier
   - `Redacted Fields Allowed` set to `*`
3. Create a second more restricted access rule with:
	- a generated API key (take note of this for later)
	- no log permissions
	- The following map permissions:
	   - Get value / inclusion proof for map keys
      - Read map mutation log entries
      - Read map mutation log tree hashes, and map tree head log
   - no account permissions
   - `Logs / maps permitted` set to name of the map created earlier
   - `Redacted Fields Allowed` set to `sequence,action,key,value,previous,timestamp,mutation_log/*,map_hash`

### Installing Golang

The Continusec Key Server is built in Go, so before continuing, [install go](https://golang.org/doc/install).

### Getting source, configuring local server

Next, grab the code for this repository:

    git clone https://github.com/continusec/key-transparency.git
    
Then make your way to the server code:

    cd key-transparency/server

And start by copying `src/config.toml.template` to `src/config.toml` and then editing:

1. For the `[server]` section, leave `disable_authentication` set to `true` for now, which prevents needing a SendGrid key for sending email, and if you are planning to use Google App Engine to run the server, set `hosted_in_app_engine` to `true`.

2. Set the `[continusec]` section to the account number, map name, and API keys as configured earlier.

3. If you are planning to run a real server, confiure the `[sendgrid]` section as appropriate. The `secret_key` field is a key for use of the [SendGrid API for sending mail](https://sendgrid.com/free/). If you left `disable_authentication` set to `true` above, then this section can be ignored.

4. You need to generate 3 keys for the `[crypto]` section:
   - `server_ec_private_key` is an EC key is used to sign server responses. Generate your own with openssl command `openssl ecparam -genkey -name prime256v1`

   - `email_token_ec_private_key` is an EC key used to sign short-lived tokens to verify the ownership of email addresses. If `disable_authentication` is set to `true`, then this key is not used at runtime, but the server will fail to start if a valid value is not present, so please generate your own with openssl command `openssl ecparam -genkey -name prime256v1` (or use the same as generated for `server_ec_private_key`).
   
   - `vuf_rsa_private_key` is an RSA key used to create a signature that forms the basis of the map key used to store the public key for a user in the Verifiable Map. We use RSA because we need a verifiable deterministic signature. To getnerate your own use this openssl command `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048`


### Running the server locally

This sample code is designed to run under Google App Engine (and that's the environment that it has had the most testing under), however it is stateless (peristent state is held by the Continusec hosted service) so it may also be run stand alone.

To run using the Google App Engine local SDK, first [download the SDK from Google](https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Go), make sure that `config.toml` has `hosted_in_app_engine` set to `true` and then start using the command:

    ./serve.sh
    
If you wish to run it standalone, then make sure that `config.toml` has `hosted_in_app_engine` set to `false` and then start using the command:

    GOPATH=$PWD:$PWD/vendor go build cksserver && ./cksserver

Either method will start the server locally on port 8080. To verify all components are running:

    curl -i http://localhost:8080/v1/publicKey/foo@bar.com
    
Will result in output similiar to:

    $ curl -i https://continusec-key-server.appspot.com/v1/publicKey/foo@bar.com
    HTTP/1.1 200 OK
    ...
    X-Body-Signature: MEUCIAp9SlSxAF9EyLxkfkB4fMYHPk0j/tYnJzKguGKT+fdOAiEAydAOl93IFUryJvm2oD771RKqMyK6g403QLtYsI7GgvQ=
    ...
    
    {"vufResult":"lJQGYwvSEpD....}

### Server Design

The Continusec Key Server is a stateless server that essentially proxies access to a [Verifiable Map](https://www.continusec.com/product/verifiable-map) hosted by [Continusec](https://www.continusec.com/).

It allows pass-through access to read-only properties of the underlying Verifiable Map (and associated Mutation and Tree Head Verifiable Logs) which allows for auditors audit the correct operation of the map.

In addition it implements special logic to setting a key/value pair in the map, where the Key Server is responsible for authorizing that access (in this case by emailing a token to the user's email address for which they are attempting to upload a public key), and then storing that data in the map in a verifiable yet privacy-preserving manner.

It achieves this by using a Verifiable Unpredictable Function to map an email address to map key (as borrowe from CONIKS) together with the selective [Redactability](https://www.continusec.com/documentation/redactability) feature offered by Continusec that allows for an entry to be partially obfuscated (such that auditors can verify the append-only nature of the map, without giving away a directory of email addresses).
