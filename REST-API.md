# Continusec Key Server REST API

The Continusec Key Server API is essentially identical to the [Continusec Verifiable Map API](https://www.continusec.com/documentation/api), and in fact all read-only operations normally available on a [Verifiable Map](https://www.continusec.com/product/verifiable-map) are also available through this API.

The Continusec Key Server is essentially a thin wrapper over the top of a [Verifiable Map](https://www.continusec.com/product/verifiable-map). The features that this wrapper provides are:

1. Alteration of a the map key via a Verifiable Unpredictable Function in order to allow mutation logs be read and verified without being susceptible to a directory harvest attack.

2. Handling of `Authorization`, that is, it adds an appropriate `Authorization` header to all read-only requests before proxying to the Continusec Map API, and has it's own business logic to validating whether setting of a key is allowed (sends a token to an email to verify ownership of email address).

3. Adds a custom `X-Body-Signature` header where it signs the body of each response.

It is suggested that readers become familiar with [Verifiable Logs](https://www.continusec.com/product/verifiable-log) and [Verifiable Maps](https://www.continusec.com/product/verifiable-map) before reading this guide.

## `GET /v1/config/vufPublicKey`

Returns the DER-encoded RSA Public Key used to verify the Verifiable Unpredictable Function.

## `GET /v1/config/serverPublicKey`

Returns the DER-encoded EC Public Key used to sign every server response. Each successful server response  includes a `X-Body-Signature` header that contains a base-64 encoded, ASN.1 ECDSA signature over the contents of the body of the response.

## `POST /v1/sendToken/user@host.com`

Body must be empty, and `Content-Length: 0` must be set. Generates a short-lived (1 hour) token and emails it to the user specified. This token may be used for subsequent requests to `PUT` a new public key for that user.

    $ curl -X POST -d "" -i https://continusec-key-server.appspot.com/v1/sendToken/info@continusec.com
    HTTP/1.1 200 OK
    
    Email sent with further instructions.

Since this results in a message being sent to a user, please only use this for your own mailboxes.

## `PUT /v1/publicKey/user@host.com`

An `Authorization` header must be set with a value received by calling `sendToken` above.

The body must be the output format of `gpg --armor --export info@continusec.com`.

For example:

    $ gpg --armor --export info@continusec.com > mypublickey
    $ curl -H "Authorization: ME0wR...EV5cNdw==" \
        -T mypublickey \
        -i https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com
    HTTP/1.1 200 OK
    X-Body-Signature: MEUC...rCPPU=
    
	{
		"mutationEntryLeafHash": "TpOI/VA2xIfd8nRgMVyMGERBwKjDEFM2ZSuT0+MAXYw="
	}

The key server:

1. Verifies that the authorization token presented is valid for the email address being set, and that it has not expired.
2. Derives the map key for the email address by applying a Verifiable Unpredictable Function (PKCS15 signature), and then hashing (SHA256) the result.
3. Retrieves the current value from the [Verifiable Map](https://www.continusec.com/product/verifiable-map) (in the form of a `publicKeyValue` record, described later) for that same user using the map key derived above.
4. Confirmed that the user currently had a different value set, and then created a new `publicKeyValue` record with an incremented `sequence` number, the `priorTreeSize` set to the size of map at time of checking, and then applied this as an [Update Map operation](https://www.continusec.com/documentation/api#mapupdate) on the underlying Verifiable Map.

The `mutationEntryLeafHash` returned is suitable for polling against the mutation log for the wrapped map if desired.

## `GET /v1/publicKey/user@host.com`

A public key can be retrieved for any user by making a `GET` request as follows:

    $ curl -i https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com
	HTTP/1.1 200 OK
	X-Body-Signature: MEQC...E/XKc4/Nw==

	{
		"vufResult": "Sb8y9aj+xVZVWi...ssWaZExzug==",
		"auditPath": [null,"RmvhRSKzzuMGMGXyr64HrncK1aBRPUKNNDjFv43dM8c=",null,...,null],
		"treeSize": 7,
		"publicKeyValue":"eyJlbWFpbCI6WyJlZWFjMm...9"
	}	
There are two parts to the response for a public key for a user. There is the public key itself, which is embedded within `publicKeyValue` and there is extra audit proof data that allows the client to verify the `publicKeyValue` returned is included in the same set of data provided to auditors to demonstrate the correct operation of the log. This extra data is equivalent to that returned by the underlying [Continsuec API for retreiving the value for a map key](https://www.continusec.com/documentation/api#mapget) however the Key Server performs one key additional step, which is that it applies the VUF to the email address passed as input and uses this as the basis for which to map to a key for the map.

The result of the VUF is returned in the response which the client should verify is correct for the email address specified.

If we base-64 decode `publicKeyValue` we see:

	{
	    "priorTreeSize": [
	        "5812222efafddc509a1b1caf86e677fba5f325cb9baef0a5d24ac8cb51c1fece", 
	        6
	    ], 
	    "sequence": [
	        "5a53188c370783aebbffb9198a193945dcdfaa17b40bc75c5999e20b084e0c5c", 
	        4
	    ], 
	    "email": [
	        "eeac2bcb27f561dc693b9e0efb12e41373155c752b8032a0d9c23740596fef09", 
	        "info@continusec.com"
	    ], 
	    "pgpPublicKey": [
	        "75151b995ed127...IEJMT0NLLS0tLS0K"
	    ]
	}

And the key data itself that was uploaded earlier is the second element under `pgpPublicKey`.

## `GET /v1/publicKey/user@host.com/at/813`

Get a public key for a user for a particular revision of the Verifiable Map. This is used for retreiving historical values.

## `GET /v1/wrappedMap/...`

Any request sent to the a path beginning with this prefix is proxied through to the underlying [Continusec API](https://www.continusec.com/documentation/api) for the [Verifiable Map](https://www.continusec.com/product/verifiable-map). This allow clients to use the [Continusec Client Libraries](https://www.continusec.com/documentation/clients) to verify the correct operation of the map and logs.

For example, if we recall from earlier the result of the `PUT` operation:

    {
    	"mutationEntryLeafHash": "TpOI/VA2xIfd8nRgMVyMGERBwKjDEFM2ZSuT0+MAXYw="
    }

This value is the leaf hash of the [Object Hash](https://www.continusec.com/documentation/objecthash) of the Mutation Log for the [Verifiable Map](https://www.continusec.com/product/verifiable-map). We can see the detail of the mutation by finding it in the Mutation Log.

First we must convert the base-64 representation in this API to the hex encoding representation needed for the [Log Inclusion Proof API](https://www.continusec.com/documentation/api#loginclusion): `4e9388fd5036c487ddf27460315c8c184441c0a8c3105336652b93d3e3005d8c`

    $ curl -i https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/0/inclusion/h/4e9388fd5036c487ddf27460315c8c184441c0a8c3105336652b93d3e3005d8c
	HTTP/1.1 200 OK
	X-Body-Signature: MEQCIDU65...5jC13Q==
	
	{
		"leaf_index": 6,
		"tree_size": 7,
		"proof": [
			"rAfDqkJ7dx8RzPHwepuqAoBCZgNt3q2KkclDsaB+t/8=",
			"JY52tEKES8oqDSPyahTECcOLMcr3smRqQJdTwBbnTfM="
		]
	}

This gives us a proof that this mutation entry was included in the mutation log, and further gives us the `leaf_index` where it was sequenced: `6`.

If we retrieve the corresponding mutation entry:

	$ curl -i https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/entry/6/xjson
	HTTP/1.1 200 OK
	X-Body-Signature: MEUCIQC...d2KsyXIetuROwE6hs=

	{
		"action": "update",
		"key": "VUm8ulDrNSQnBYOvV+WSAkJ5Kc6BDB5qnsjYvsDvqSo=",
		"previous": "waljOTasyqD8MX0EUhVSsjEidHBskp8xWp5hTbStYB8=",
		"timestamp": "2016-07-30T05:34:42.464109425Z",
		"value": "dDuoBQfhaHUiydcg7rsLr3wCzrD3oTjVi6DiX9O15GE="
	}
	
We can see update of the specified key (which is the base-64 encoded value of the SHA256 of the result of the VUF shown above) to the [object hash](https://www.continusec.com/documentation/objecthash) for `publicKeyData` record above, to be applied only if the value at time of application is the value specified as `previous` above.

Note however that if we were to directly retrieve the value for the key in the mutation log via the proxied Continusec API (rather than using the Key Server `GET /v1/publicKey/user@host.com` API, we get a [redacted](https://www.continusec.com/documentation/redactability) version of the same `publicKeyData` record above:

	$ curl -i https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0/key/h/5549bcba50eb3524270583af57e59202427929ce810c1e6a9ec8d8bec0efa92a/xjson
	HTTP/1.1 200 OK
	X-Verified-Treesize: 7
	X-Verified-Proof: 1/466be14522b3cee3063065f2afae07ae770ad5a0513d428d3438c5bf8ddd33c7

	{
		"email": "***REDACTED*** Hash: 612d6f2eb5279e06003a69290a2cc0642c5d8f2847d22d29ceecf296a9744670",
		"pgpPublicKey": "***REDACTED*** Hash: bb77f7049cde4c423bb2f4f3cae64be6d951d932209b79058fe80c369556724e",
		"priorTreeSize": "***REDACTED*** Hash: c8badf6d788e663c8370ac3b09430fd820bfb87f211594cf125cfc628137123f",
		"sequence": [
			"5a53188c370783aebbffb9198a193945dcdfaa17b40bc75c5999e20b084e0c5c",
			4
		]
	}

Note that the same data is returned (if you take the [Object Hash](https://www.continusec.com/documentation/objecthash) you get the same result, whether [redacted](https://www.continusec.com/documentation/redactability) or not) meaning that an auditor can make use of this data to properly audit the correct operation of the Verifiable Map, and even audit the correct operation of the Key Server in that is always increments sequence numbers with no gaps, since that data is left unredacted, however the underlying email address used to derive the map key, and the underlying PGP Public Key Certificate (that also contains the email address) is kept private.

# Questions / feedback?

For any questions / feedback, please open an issue in Github, or send mail to: <support@continusec.com>

The primary purpose of developing the Continusec Key Server was to provide an effective demonstration of the capabilities of the [Continusec Verifiable Data Structures API](https://www.continusec.com/).

We thank the [CONIKS](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-melara.pdf) folk for the inspiration to build this demonstration.

