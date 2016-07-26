# Continusec Key Server

This project contains the source code for a [CONIKS](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-melara.pdf)-inspired Key Transparency server that provides an effective demonstration of how to use the [Continusec Verifiable Data Structures API](https://www.continusec.com/) to produce a verifiable and trustworthy service.

A running version of this code can be found at:

[https://continusec-key-server.appspot.com/](https://continusec-key-server.appspot.com/)

This repository consists of two sections:

1. `server` - The source code for the Key Server
2. `client` - The source code for a client that can talk to that Key Server

This document describes the HTTP API provided by the server, and corresponding `README` files within both the server and the client go into detail on how to run your own version of the server, and how to use the client, which automates all of the detail displayed below.

## What exactly is the server?

The Continusec Key Server provides a [Verifiable Map](https://www.continusec.com/product/verifiable-map) of Email addresses to PGP Public Keys with the following properties:

- Any user may add or update their own public key to this map.

- Any user may efficiently detect changes to their own key, or other keys that they are interested in.

- Any user may efficiently defend against a split-view attack by gossip of a single tree hash.

- Any interested party may fetch the current or historical public key for a known user.

- Any interested party may audit the correct operation of the map by downloading all entries, without being able to gain a directory of email addresses.

## How does it work?

The following is complex - users are recommended to use the client which hides this, however we include the below to document how the server operates.

Let's work through some examples.


### Example 1: Uploading a public key

We'll start by uploading a public key for our email address: `info@continusec.com`

#### Step 1: Request a token to upload a key

    $ curl -X POST -d "" -i https://continusec-key-server.appspot.com/v1/sendToken/info@continusec.com
    HTTP/1.1 200 OK
    
    Email sent with further instructions.

Results in a email being received to the address requested (so please only request these for email addresses that you own) that includes a token needed for the next step.

#### Step 2: Upload public key to the Key Server

    $ gpg --export info@continusec.com > mypublickey.der
    $ curl -H "Authorization: ME0wR...EV5cNdw==" \
        -i -X PUT https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com -d @mypublickey.der
    HTTP/1.1 200 OK
    X-Body-Signature: MEUC...rCPPU=
    
    {
    	"mutationEntryLeafHash": "TwNVzzrNKXbpNVXeahgJ/IDDYS5zCYu2OiJtZ/NAABY="
    }

In this step we export our public key, and then we `PUT` this to our address on the server. If the token is successfully validated by the server, and if the public key uploaded differs from what is already there, a successful response is returned.

We'll discuss in detail what this response means later.

That's it, we've uploaded our public key to the key server.

### Example 2: Retrieving the current public key

A public key can be retrieved for any user by making a `GET` request as follows:

    $ curl -i https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com
	HTTP/1.1 200 OK
	X-Body-Signature: MEQCIGa6BK7WU2gPMp4av2jccNYs65CooGJaoIIQ3d++EdKEAiAKQq8fOLTHf+Ng5lsApVNi5gFMISxEWL1+tE/XKc4/Nw==

	{
		"vufResult": "Sb8y9aj+xVZVWiQTs3vmN3bFb+O88C1hF+y75EZ5RGaq0XQetjURPu6BAaB1zR94wh0+zNBQiIaQAtnDRa3VPs0N5dPxAoVi38ZqYvVklxRPiTRVkHYCAufjzY/RTzEnSToxczej59PV8I2nZIT144TPBPGu1dwynyU1TkTkn3TZEp7AdR8Mmrp60b2U/rAnmf15ljbcSmzwH1wj2Zh3k5jq0rbSg6lTD1/t1dmB0SKQ5C0k0xxKQpypNkkiEndPTeP9TsIO7ckqhVusMUuUfugNsDpYURFh2kPvQ6fy/na5W80QcM+muqp+BifBzDv6QtuNxX1KfRgMssWaZExzug==",
		"auditPath": [
			"z2jKRP9sBtLLWfnQK7QCOlgfjY6mgL+M2Ypc04hgsVc=","dgC1+LbA5C6pwUXOn6LvSSgRJuP4ocJ2zsKqCOXCNWA=",
			null,null,null,null, ... ,null
		],
		"treeSize": 6,
		"publicKeyValue": "eyJlbWFpbCI6WyIxNjYwMTA0ZjkxMGVhY2E4MmNmMTkxZmJjOGQzNTg0MTYxYjAwMDdkMmJjNWFkMWY2YzJmMTNiNzU3MjVlZWYwIiwiaW5mb0Bjb250aW51c2VjLmNvbSJdLCJwZ3BQdWJsaWNLZXkiOlsiNTFlMTVmYzVjYmJlNWRiNjFmM2FmM2MwMTRlZmFjYjU1NzhkZGI1ZDI5NDJkNTg5ZWU0OWE4M2JlNGU1YTJmNSIsIm1RRXBsU01vcnBKMGM5QlUrMVVMQkJZQ0F3RUNIZ0VDRjRBSkVEZkc2S08yeElyUW44c0k1bWxScy9zeC9ydGRwSG9tRy83NHhCMkx0YlEwSUdOMzgvb3ZIeVFPdVZsd1N6RjZhS25ZVFVoUE9pdWRDRzA1bGpBcTUvZEF6NGwraWozWDIyZUdkT3JDWHVTRjhkVml5TzhxL09oRkNSQTN4dWlqdHNTSzBIa1VDSk9wYmVtYnNzYTBmT1VjcVVwWHVrTDNrQkpoZDZHOHl6OEJEeXFWMEp4R3pIdEpIYzZ1THU2VmZBZ1RERG9IRG50c3VhVFpPU0pRbWdGY3hMSXNzOTZ3Sjd1eWpHaTFaaHJIb3Y3SlJRNnkvZGQ4Y0JTeGIwUTRCVzVCekZEY1piZEVVQWlGR05XNUw1TTJNSndKZmZsUDA2Ujl2ZE9RVk9XZXdIZmFSUTVtM1BMTnpkdktQejd2WmROU3NqV0R3VTE0dG9kT1hFcndZNURUcUJ0STMrWnM5QlBMODNkTitoRXRZZ1ZqSWlwa2VzeFI2K1JRSHdMMTR4WEFXNnhGTUw3V3hKTFlCenowMWhEd1c1ek00aFpHUUFqdTFuc2g5M3dteW5BV1JRVGZNZz09Il0sInByaW9yVHJlZVNpemUiOlsiNzlhNDM1Zjc4NGY1ZDU1NTVhZWEzNTVmMjVmNjAwZDI0ZDQzNTcxMGJmNDQ5ZGFhYWQ5OGM2NTMwYWYxMWFhZSIsNV0sInNlcXVlbmNlIjpbImRkZTg0MGZhMGNhN2UwYmRlMmRiNTFhYjcwOWQ1Mjc2NjgyZjY4ZjY5OWYxY2ZmNjZmMWIwY2NkYzVhZWI4MzgiLDBdfQ=="
	}
	
There are two parts to the response for a public key for a user. There is the public key itself, which is squirrelled away inside of `publicKeyValue` and there is extra audit proof data that allows the client to verify the `publicKeyValue` returned is included in the same set of data provided to auditors to demonstrate the correct operation of the log. This extra data is equivalent to that returned by the underlying [Continsuec API for retreiving the value for a map key](https://www.continusec.com/documentation/api#mapget) however the Key Server performs one key additional step, which is that it applies the VUF to the email address passed as input and uses this as the basis for which to map to a key for the map.

The result of the VUF is returned in the response which the client should verify is correct for the email address specified.

If we base-64 decode `publicKeyValue` we see:

	{
		"email": [
			"1660104f910eaca82cf191fbc8d3584161b0007d2bc5ad1f6c2f13b75725eef0",
			"info@continusec.com"
		],
		"pgpPublicKey": [
			"51e15fc5cbbe5db61f3af3c014efacb5578ddb5d2942d589ee49a83be4e5a2f5",
			"mQEplSMorpJ0c9BU+1ULBBYCAwECHgECF4AJEDfG6KO2xIrQn8sI5mlRs/sx/rtdpHomG/74xB2LtbQ0IGN38/ovHyQOuVlwSzF6aKnYTUhPOiudCG05ljAq5/dAz4l+ij3X22eGdOrCXuSF8dViyO8q/OhFCRA3xuijtsSK0HkUCJOpbembssa0fOUcqUpXukL3kBJhd6G8yz8BDyqV0JxGzHtJHc6uLu6VfAgTDDoHDntsuaTZOSJQmgFcxLIss96wJ7uyjGi1ZhrHov7JRQ6y/dd8cBSxb0Q4BW5BzFDcZbdEUAiFGNW5L5M2MJwJfflP06R9vdOQVOWewHfaRQ5m3PLNzdvKPz7vZdNSsjWDwU14todOXErwY5DTqBtI3+Zs9BPL83dN+hEtYgVjIipkesxR6+RQHwL14xXAW6xFML7WxJLYBzz01hDwW5zM4hZGQAju1nsh93wmynAWRQTfMg=="
		],
		"priorTreeSize":[
			"79a435f784f5d5555aea355f25f600d24d435710bf449daaad98c6530af11aae",
			5
		],
		"sequence":[
			"dde840fa0ca7e0bde2db51ab709d5276682f68f699f1cff66f1b0ccdc5aeb838",
			0
		]
	}

And the key data itself that was uploaded earlier is the second element under `pgpPublicKey`.

#### The `publicKeyValue` record

When we uploaded the public key earlier the key server did the following:

1. Verified that the authorization token presented was valid for the email address being set, and that it has not expired.
2. Derived the map key for the email address by applying a Verifiable Unpredictable Function (PKCS15 signature), and then hashing (SHA256) the result.
3. Retrieved the current value from the [Verifiable Map](https://www.continusec.com/product/verifiable-map) (in the form of a `publicKeyValue` record) for that same user.
4. Confirmed that the user currently had a different value (in this case, an empty value) set, and then created a new `publicKeyValue` record with an incremented `sequence` number, the `priorTreeSize` set to the size of map at time of checking, and then applied this as an [Update Map operation](https://www.continusec.com/documentation/api#mapupdate) on the underlying Verifiable Map.

If we recall from earlier the result of the `PUT` operation:

    {
    	"mutationEntryLeafHash": "TwNVzzrNKXbpNVXeahgJ/IDDYS5zCYu2OiJtZ/NAABY="
    }

This value is the leaf hash of the [Object Hash](https://www.continusec.com/documentation/objecthash) of the Mutation Log for the [Verifiable Map](https://www.continusec.com/product/verifiable-map). We can see the detail of the mutation by finding it in the Mutation Log:

##### Prove inclusion in the mutation log

First we must convert the base-64 representation in this API to the hex encoding representation needed for the [Log Inclusion Proof API](https://www.continusec.com/documentation/api#loginclusion): `4f0355cf3acd2976e93555de6a1809fc80c3612e73098bb63a226d67f3400016`

    $ curl -i https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/0/inclusion/h/4f0355cf3acd2976e93555de6a1809fc80c3612e73098bb63a226d67f3400016
	HTTP/1.1 200 OK
	X-Body-Signature: MEQCIDU6522WkGYVo976KQ1kMsJsrlG5WpY2acViUQxh0JIWAiAmgU1bT0ciDZoxtKRePa7o0mMJ/yrtJyUL13Ps5jC13Q==
	
	{
		"leaf_index": 5,
		"tree_size": 6,
		"proof": [
			"+FimHvi/PjTtPJf0lWj7qhAH0232LPuRpUpc7zgvpEE=",
			"0tGBxMjOM8HanZ0fLvV4CT4hXTRjHgNxuA3d5Kgr+Mw="
		]
	}

This gives us a proof that this mutation entry was included in the mutation log, and further gives us the `leaf_index` where it was sequenced: `5`.

If we retrieve the corresponding mutation entry:

	$ curl -i https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/entry/5/xjson
	HTTP/1.1 200 OK
	X-Body-Signature: MEUCIQCwbgEg376x+g3e7VxCpZFdEwcZ8S3x0f6dfbbZo96wTwIgOf4fJqNX5mqKBbY1bj9UxYSXQhd2KsyXIetuROwE6hs=

	{
		"timestamp": "2016-07-26T06:16:36.031721219Z",
		"action": "update",
		"key": "VUm8ulDrNSQnBYOvV+WSAkJ5Kc6BDB5qnsjYvsDvqSo=",
		"previous": "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
		"value": "5yHVdCpW//bXNfc4JPPxTYL/S/bSepj4a2ONH82GChg="
	}
	
We can see update of the specified key (which is the base-64 encoded value of the SHA256 of the result of the VUF shown above) to the object hash for `publicKeyData` record above, to be applied only if the value at time of application is the value specified as `previous` above. `bjQLn....` is the leaf hash for an empty node.

Note however that if we were to directly retrieve the value for the key in the mutation log via the proxied Continusec API (rather than using the specific `GET /v1/publicKey/user@host.com` API, we get a redacted version of the same `publicKeyData` record above:

	$ curl -i https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0/key/h/5549bcba50eb3524270583af57e59202427929ce810c1e6a9ec8d8bec0efa92a/xjson
	HTTP/1.1 200 OK
	X-Verified-Proof: 0/cf68ca44ff6c06d2cb59f9d02bb4023a581f8d8ea680bf8cd98a5cd38860b157,1/7600b5f8b6c0e42ea9c145ce9fa2ef49281126e3f8a1c276cec2aa08e5c23560
	X-Verified-Treesize: 6
	X-Body-Signature: MEYCIQCkE1yHpa3ov3fRs+Sy/2zvR7SB03dkaURhFKd9N9jMJgIhAOs4HaiEWcRqwyln0yxQt9jWI7hH3dk+VNoYy6laPE9Y

	{
		"email": "***REDACTED*** Hash: a5373dbf373eb9f1c698b2df002450b972213400949b61ba0964a8d871d7521d",
		"pgpPublicKey": "***REDACTED*** Hash: 3d5bcc601057da75b7f7b6c0b9d5eff875a5afbadfc3c9d6f85e8bcbe06ff2f7",
		"priorTreeSize": "***REDACTED*** Hash: f119ae85be6373dd6f83e99327c453478b578f2e3ef59a27a29d2bccf5cb62e3",
		"sequence": [
			"dde840fa0ca7e0bde2db51ab709d5276682f68f699f1cff66f1b0ccdc5aeb838",
			0
		]
	}

Note that the same data is returned (if you take the [Object Hash](https://www.continusec.com/documentation/objecthash) you get the same result, whether [redacted](https://www.continusec.com/documentation/redactability) or not) meaning that an auditor can make use of this data to properly audit the correct operation of the Verifiable Map, and even audit the correct operation of the Key Server in that is always increments sequence numbers with no gaps, since that data is left unredacted, however the underlying email address used to derive the map key, and the underlying PGP Public Key Certificate (that also contains the email address) is kept private.


## Other APIs provided by the server

The server supports the following APIs:

    GET /v1/config/vufPublicKey

Returns the DER-encoded RSA Public Key used for the Verifiable Unpredictable Function.

    GET /v1/config/serverPublicKey
    
Returns the DER-encoded EC Public Key used to sign every server response. Each successful server response  includes a `X-Body-Signature` header that contains a base-64 encoded, ASN1 ECDSA signature over the contents of the body of the response.

    GET /v1/publicKey/user@host.com/at/123

Get a public key for a user for a particular revision of the verifiable map. This is used for retreiving historical values.
