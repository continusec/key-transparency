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

And start by editing `src/config.toml`:

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

### API Provided by the server

The server supports the following APIs:

    GET /v1/config/vufPublicKey

Returns the DER-encoded RSA Public Key used for the Verifiable Unpredictable Function.

    GET /v1/config/serverPublicKey
    
Returns the DER-encoded EC Public Key used to sign every server response. Each successful server response  includes a `X-Body-Signature` header that contains a base-64 encoded, ASN1 ECDSA signature over the contents of the body of the response.

    POST /v1/sendToken/user@host.com
    
POSTing to this endpoint will cause the server to send an email to the address specified that contains a short-lived (currently 1 hour) authorization token suitable for use in setting the public key for a user.

    PUT /v1/publicKey/user@host.com
    Authorization: <token received by email>
    
    <key data in body>

This API will set a new value for the public key for a user. The key data should be the output of `gpg --export user@host.com` When the server receives this request it will look up the current public key for the user, increment the sequence number by 1, and then send an [update mutation to the Verifiable Map](https://www.continusec.com/documentation/api#mapupdate) which in turn will shortly be reflected in the Verifiable Map. The return value for this is the leaf hash of an entry to the mutation log, which in turn can be polled to determine when it has been incorporated.

    GET /v1/publicKey/user@host.com
    
Get the latest public key set for a user. See worked example below for details on the format of the response.

    GET /v1/publicKey/user@host.com/at/123

Get a public key for a user for a particular revision of the verifiable map. This is used for retreiving historical values.

    GET /v1/wrappedMap/.*

Any `GET` request sent to this path is proxied to the underlying Verifiable Map and Verifiable Logs provided by the [Continusec API](https://www.continusec.com/documentation/api). These may be used by generic audit tools (such as those provided in the [Continusec Go Client Library](https://github.com/continusec/go-client) to audit the correct operation of the Verifiable Map.

#### Worked example

    $ curl -i -X POST -d "" https://continusec-key-server.appspot.com/v1/sendToken/info@continusec.com
    HTTP/1.1 200 OK
    ...
    Email sent with further instructions.

Email received with token, now let's set a key based on the token received in the message:

    $ gpg --export info@continusec.com | curl -H "Authorization: MEwwRAIgQ5l+limIQ618HE6Kv6Ny9VsmMHLQeeuOZ3nRStxKFkkCIF5TNVcI5IvSsmt/N2LRQOa3xmkIbR7IrMBEIpnRKYSdAgRXlvYz" \
        -i -X PUT https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com -d @-
    HTTP/1.1 200 OK
    ...
    X-Body-Signature: MEUCIQCJd9m0rzbExfnCC/YMgbFFHALY+5ta9bS3v4vhVVNYYAIgCeUkENlAJB5ojDu+RzwBFz+QrSNorSVkwP/krfNW2Nk=
    ...
    {"mutationEntryLeafHash":"qsAXm3yawpNJXxg9VFses/xQu525rIv09gsGhXksn8w="}

(optional) Check for inclusion in the mutation log for the wrapped map (we first convert the base-64 encoding to hex encoding):

    $ curl -i https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/0/inclusion/h/aac0179b7c9ac293495f183d545b1eb3fc50bb9db9ac8bf4f60b0685792c9fcc
    HTTP/1.1 200 OK
    ...
    X-Body-Signature: MEQCIFPDbdLgcrBWF+vJCq1Gt7bG2r2ngkjETV7B7ECqEnjsAiBwv4LJTUXhAKwSuUDu3EarXuhBAwXi5nhojlzlrzVpYw==
    ...
    {"leaf_index":13,"tree_size":14,"proof":["O/ZnKcie4t5wAnVaBuMsyStrXA5yUT3Tx1NFwnbMcw0=","EwJQuukpFPNTVIEKBQ5pM6du1av73Sr5i2I6hIHusUI=","65VGCp9sJ5fK0hFLv7tPLvg42ZTWplStj8o/frotb1w="]}
    
Get the current key for this user:

    $ curl -i https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com
    HTTP/1.1 200 OK
    ...
    X-Body-Signature: MEQCIEs1l/sQsXyb1hNGXWrhyJN2T0triX/rh0WwZF/7y/HdAiAg5wpDhM59yAmbkF7uckOmomHGvL0xLcpvXhdezwyE5g==
    ...

    {
        "vufResult":"h+XweINtgUlaEiMf4o19sTwlJqrWNV114BbFtF53BMvUczoZhNkVaNOVKabKvM3LIyrqCRzmzZYOKV2x9l+sXERClTbGInJIL1QkqMeaT99v+C1MOeSzaj2HuKal6iXnqFMbS6quHGmZ5/RwLn3NWVFWsS4aLZyID6oErV01e197hf45oFj9asfvFMB6NhvwATLFmLavlwDN8rb259Y8jIKQ5itQrDDklSqC7RV4pa4XBaH/3WO57JKrr1i7yiyJfKc+atz1/0APOealh1KwcRUypSQThMNhGH39msKDolsouDmo37eddcROfhsqXR/5d27rZwlbqPrwgZ0nbzvlWQ==",
        "auditPath":["PFLykuEgzfefhcRzWNQy5H4EtMDjLy51nkADHzlhW3s=",null,"TOyon/mJfiCjAa+ivZwkT7WrHLdtZwJEIYlZ8RyU1l0=",null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null],
        "treeSize":14,
        "publicKeyValue":"eyJlbWFpbCI6WyJjNjY1ZmU2NzljMTExOWVjMTVjNTlmOGY4MmQ3NjEzODZmYTVjYWYyMDI2ZjhhOTFmNGJjNzViMjc4MzIwZjBjIiwiaW5mb0Bjb250aW51c2VjLmNvbSJdLCJwZ3BQdWJsaWNLZXkiOlsiYjljYzE5OTI5YTIxMTZmYmJhMmQxMWI3M2I0MzI2MzllNDY4OTY0ZDczOWM5OTQ3ZDI5ZWY1MTI4ODk1ZDZmMSIsIm1RRXBsU01vcnBKMGM5QlUrMVVMQkJZQ0F3RUNIZ0VDRjRBSkVEZkc2S08yeElyUW44c0k1bWxScy9zeC9ydGRwSG9tRy83NHhCMkx0YlEwSUdOMzgvb3ZIeVFPdVZsd1N6RjZhS25ZVFVoUE9pdWRDRzA1bGpBcTUvZEF6NGwraWozWDIyZUdkT3JDWHVTRjhkVml5TzhxL09oRkNSQTN4dWlqdHNTSzBIa1VDSk9wYmVtYnNzYTBmT1VjcVVwWHVrTDNrQkpoZDZHOHl6OEJEeXFWMEp4R3pIdEpIYzZ1THU2VmZBZ1RERG9IRG50c3VhVFpPU0pRbWdGY3hMSXNzOTZ3Sjd1eWpHaTFaaHJIb3Y3SlJRNnkvZGQ4Y0JTeGIwUTRCVzVCekZEY1piZEVVQWlGR05XNUw1TTJNSndKZmZsUDA2Ujl2ZE9RVk9XZXdIZmFSUTVtM1BMTnpkdktQejd2WmROU3NqV0R3VTE0dG9kT1hFcndZNURUcUJ0STMrWnM5QlBMODNkTitoRXRZZ1ZqSWlwa2VzeFI2K1JRSHdMMTR4WEFXNnhGTUw3V3hKTFlCenowMWhEd1c1ek00aFpHUUFqdTFuc2g5M3dteW5BV1JRVGZNZz09Il0sInByaW9yVHJlZVNpemUiOlsiMTIyN2UwNDUzODQzZjUxYmIyMTUyMGYzYzhmMjllMWRiODNlZjdlMTU2OTFmZDQyNWYxYjA0ZjZhZGU4MDE1NyIsMTNdLCJzZXF1ZW5jZSI6WyI2OWJjMjM0NWE1MDBkOWNiMmI3MDNjNDM1N2ExMWU4OTgxMmE4Njk0ZDJkY2FhNzViYTE4NWUwMTU2OWFmYWMyIiwwXX0="
    }


This result is equivalent to that returned by the underlying [Continsuec API for retreiving the value for a map key](https://www.continusec.com/documentation/api#mapget) however the Key Server performs one key additional step, which is that it applies the VUF to the email address passed as input and uses this as the basis for which to map to a key for the map.

The result of the VUF is returned in the response which the client should verify is correct for the email address specified.

The `publicKeyValue` is the actual value stored in the Verifiable Map, which, for the example above, base-64 decoded, is:

    {
        "email":[
            "c665fe679c1119ec15c59f8f82d761386fa5caf2026f8a91f4bc75b278320f0c",
            "info@continusec.com"
        ],
        "pgpPublicKey":[
            "b9cc19929a2116fbba2d11b73b432639e468964d739c9947d29ef5128895d6f1",
            "mQEplSMorpJ0c9BU+1ULBBYCAwECHgECF4AJEDfG6KO2xIrQn8sI5mlRs/sx/rtdpHomG/74xB2LtbQ0IGN38/ovHyQOuVlwSzF6aKnYTUhPOiudCG05ljAq5/dAz4l+ij3X22eGdOrCXuSF8dViyO8q/OhFCRA3xuijtsSK0HkUCJOpbembssa0fOUcqUpXukL3kBJhd6G8yz8BDyqV0JxGzHtJHc6uLu6VfAgTDDoHDntsuaTZOSJQmgFcxLIss96wJ7uyjGi1ZhrHov7JRQ6y/dd8cBSxb0Q4BW5BzFDcZbdEUAiFGNW5L5M2MJwJfflP06R9vdOQVOWewHfaRQ5m3PLNzdvKPz7vZdNSsjWDwU14todOXErwY5DTqBtI3+Zs9BPL83dN+hEtYgVjIipkesxR6+RQHwL14xXAW6xFML7WxJLYBzz01hDwW5zM4hZGQAju1nsh93wmynAWRQTfMg=="
        ],
        "priorTreeSize":[
            "1227e0453843f51bb21520f3c8f29e1db83ef7e15691fd425f1b04f6ade80157",
            13
        ],
        "sequence":[
            "69bc2345a500d9cb2b703c4357a11e89812a8694d2dcaa75ba185e01569afac2",
            0
        ]
    }

Each field in the object has been converted to a redactable nonce pair (see [Redactability](https://www.continusec.com/documentation/redactability)). While all fields are visible in this view, an auditor that is using the generic map and log APIs to verify correct operation of the server would see this equivalent redacted view (the key in the request is `hex-encoding(sha256(base-64-decode(vuf-result-above)))`):

    $ curl -i https://continusec-key-server.appspot.com/v1/wrappedMap/tree/14/key/h/8b2fbfa8490ee78bc097c3542bd2cde7e99745a550d14cbd2326a96d08d198c7/xjson
    HTTP/1.1 200 OK
    ...
    X-Body-Signature: MEYCIQDxweiye1faGiCSUpi8WxwtxK7sNnxnyL+99xQLBfgQmwIhAOSs7NtZXF6B8MIu1OtwoFXtZcBe8OKc4QvZ4cxyQuBN

    ...

    {
        "email":"***REDACTED*** Hash: 0ae264ba75f4b50ef32d851267352f89c75658c80444069507ad8e17d6aa294c",
        "pgpPublicKey":"***REDACTED*** Hash: 2f8731ca76deaf4a664672bd265ee82567d71cfd8eaf5b37203c2c943c9f5f17",
        "priorTreeSize":"***REDACTED*** Hash: d85d4d19101e872b6040c8d3f775b728e411ac443a9ae2b47057e1ba67d0b018",
        "sequence":[
            "69bc2345a500d9cb2b703c4357a11e89812a8694d2dcaa75ba185e01569afac2",
            0
        ]
    }

This redacted form shows only the sequence number - this is so that an auditor of the Verifiable Map, could, in addition to auditing the correct general operation of a map, also audit the the Key Server only increments this sequence over time.

All other fields are redacted so that an auditor cannot deduce the email addresses stored within a Verifiable Map, even though they have nearly full access to the content within. Since we are using [Object Hash](https://www.continusec.com/documentation/objecthash) to calculate the leaf hash for these entries in the map, both the redacted and unredacted forms produce the same object hash result, and thus an auditor can be satisfied as to the correct operation of the map, without sacrificing the privacy preserving properties.