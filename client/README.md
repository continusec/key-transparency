# Continusec Key Server Client

This directory contains a client for the Continusec Key Server.

## Installation

The client is written in Go, please begin by installing the Go compiler from: <https://golang.org/doc/install>.

Once installed, install the client:

    go get github.com/continusec/key-transparency/client/cmd/cks

And then to run:

    cks help

## Getting Started

The `cks` application maintains state in `$HOME/.cksdb`. This state is used to verify consistency of answers returned by the server, and also maintains a cache of all responses received from the key server.

To initialize the state, run:

    cks init

Since this will remove any existing local database, it will prompt before continuing:

    Initialize new database with server: https://continusec-key-server.appspot.com? (this will overwrite any existing database) Type yes or no to continue:
    
Type `yes` to continue, or invoke with `--yes` to bypass the prompt.

If you wish to test with a different server, for example for testing your own server, invoke with the `--server` option as follows:

    cks init --server http://localhost:8080
    
During initializing any requests sent to the server will be printed, for example:

	Fetching: https://continusec-key-server.appspot.com/v1/config/serverPublicKey
	Fetching: https://continusec-key-server.appspot.com/v1/config/vufPublicKey
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/treehead/tree/0
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/treehead/tree/6/inclusion/h/91a287ccbe6c0dcb94c50a973482500202c3330417e3ecb561049e592faf7cf5
	Initialization complete.

## Tracking Server State

A new Continusec Key Server begins at sequence 0 which increases over time as entries are modified. The client keeps track of what sequence number is currently in effect.

To see the current sequence number in effect:

    cks status

Results in:

    Tracking revision: 6

To check for updates from the server use:

    cks update

Which shows any requests sent to the server for fresh state, and completes by displaying the revision in effect (in this case, unchanged):

    Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0
    Tracking revision: 6

If desired once can request that the client act upon an earlier version of server state, this is done by passing a sequence number as an argument like follows:

    cks update 4

Which in our client resulted in the following requests:

	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/4
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/6/consistency/4
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/treehead/tree/6/inclusion/h/171f79df147a5f4070718de0f7d4b4b2e60c4e48f4b749ec1cb4f2c50119d28d
	Tracking revision: 4

## Gossip

It can be useful to output a small piece of information that can be gossiped to detect misbehavior by the key server:

    cks gossip
    
Will output such information, suitable for automated processing:

    {
    	"thlth": "eyJ0cmVlX3NpemUiOjYsInRyZWVfaGFzaCI6IkQ3aXoyaU9qWjJpQVl0MWtGYmR6UnJWNzdQT2NhNnV2djl0SHVQUTlLbkU9In0K"
    	"sig": "MEUCICwAI5MG/Jp2OGrLSM+A2jzrJ+L6TbjpR+4qaoBSOLBgAiEAp04Vnl9s+x2b17Fu3AWvYQwNm6yfvXzh42bZ6dZ0mNw=",
    }
    
The `thlth` field is base-64 encoded JSON as received by the client for the latest tree head log tree head for the map and the `sig` field is the base-64 encoded ASN.1 signature over the JSON bytes as returned by the Key Server.

If two inconsistent `thlth` values are emitted by the Key Server, that is a sign of misbehavior.

## Uploading your own public key

To upload your own public key, either new or as an update, first export it from `gpg` (or whatever tool is used):

    gpg --export info@continusec.com > mypublickey.bin

Then request an authorization token to your email address, for example:

    cks mail info@continusec.com

Type `yes` to continue:

    Are you sure you want to generate and send a token to address (info@continusec.com)? Please only do so if you own that email account. Type yes or no to continue: yes

And upon success:

	Sending mail to info@continusec.com with token...
	Success. See email for further instructions.

Wait for an email including the token, and then use this to upload the key saved above as follows:

    cks upload info@continusec.com mypublickey.bin ME0wRQIgZIox0Bf20Fg9xschAljhuhrhXZMlKbEUCm8i5fl+9ywCIQCf3hRuTUxHt+ax931slp2NWks+XfgYmQpxgnt0PE9PzwIEV5gh9w==

Result:

	Setting key for info@continusec.com with token...
	Success. Leaf hash of mutation: 6zKhd6VNsNBTAK4YIev9DhXv/WjJwGS8JSZiiKQPcnw=

Done, your key has been added to the key server.

To see the status of update key requests:

	cks log

Will show a table of updates:

	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+-------------------+---------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              |   MAP SEQUENCE    | USER SEQUENCE |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+-------------------+---------------+
	| info@continusec.com | vaZavgQqsBO2lerkknfBeKieJpbyH1skixbbWhj8+o8= | 2016-07-27 12:49:19 | 6zKhd6VNsNBTAK4YIev9DhXv/WjJwGS8JSZiiKQPcnw= | Not yet sequenced |               |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+-------------------+---------------+

To refresh this table:

    cks update

Result:

	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0
	Tracking revision: 8
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/8/inclusion/h/eb32a177a54db0d05300ae1821ebfd0e15effd68c9c064bc25266288a40f727c
	Fetching: https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com/at/8
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+---------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              | MAP SEQUENCE | USER SEQUENCE |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+---------------+
	| info@continusec.com | vaZavgQqsBO2lerkknfBeKieJpbyH1skixbbWhj8+o8= | 2016-07-27 12:49:19 | 6zKhd6VNsNBTAK4YIev9DhXv/WjJwGS8JSZiiKQPcnw= |            7 |             2 |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+---------------+

`Not yet sequenced` means that the mutation log entry has not yet been sequenced and added to the map. Once it has been sequenced (that is a number appears in this column), then any revision of the map *greater than* that number will reflect this value. So here mutation 7 is reflected in map sequence number 8 and beyond.

The `User sequence` column shows an increasing sequence number for just this user. The initial value for each user is 0 and this increases with each successful update. If a fresh update is requested for a user while another update is pending to apply, it will result in a `Conflict - not sequenced` message like below:

	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              | MAP SEQUENCE |      USER SEQUENCE       |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	| info@continusec.com | eMV5VioXJp8O9ZmHxG08Ys4yFKOcdzy1OpOkCNNYqKk= | 2016-07-27 13:53:01 | kI5hSGAy8WPas7QrwnGprWFNZQbU45zjx7/TBkF6BWM= |           10 |                        5 |
	| info@continusec.com | 50MF8B60FVuGPcS7fc7Q2sAxaAKZaNYXK+/040qcR+k= | 2016-07-27 13:53:05 | afg2Vik+q1g5kCUcTEO9kx4zMk0tjUWHtO+AhWLYp7U= |           11 | Conflict - not sequenced |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+

This occurs as each update request is conditional on a previous value - here the previous value (map sequence number 10) was not yet available when map sequence 11 was requested, and as such it was never applied to the map. In such a case you can simply try again:

	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              | MAP SEQUENCE |      USER SEQUENCE       |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	| info@continusec.com | eMV5VioXJp8O9ZmHxG08Ys4yFKOcdzy1OpOkCNNYqKk= | 2016-07-27 13:53:01 | kI5hSGAy8WPas7QrwnGprWFNZQbU45zjx7/TBkF6BWM= |           10 |                        5 |
	| info@continusec.com | 50MF8B60FVuGPcS7fc7Q2sAxaAKZaNYXK+/040qcR+k= | 2016-07-27 13:53:05 | afg2Vik+q1g5kCUcTEO9kx4zMk0tjUWHtO+AhWLYp7U= |           11 | Conflict - not sequenced |
	| info@continusec.com | 50MF8B60FVuGPcS7fc7Q2sAxaAKZaNYXK+/040qcR+k= | 2016-07-27 13:55:56 | 1r3bFYbvaSNpu1sh+fajzLz17iPq7kT7SvFbSBpTVPk= |           12 |                        6 |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+

It is also possible to see multiple entries with the same `Value Hash` and `User Sequence` - this occurs if duplicate requests arrive at once. Technically only one of the mutation operation actually takes effect, however for the purpose of the console report we simply show th same user sequence against each, signifying that that value hash was in effect at that map mutation size.

	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              | MAP SEQUENCE |      USER SEQUENCE       |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	| info@continusec.com | eMV5VioXJp8O9ZmHxG08Ys4yFKOcdzy1OpOkCNNYqKk= | 2016-07-27 13:53:01 | kI5hSGAy8WPas7QrwnGprWFNZQbU45zjx7/TBkF6BWM= |           10 |                        5 |
	| info@continusec.com | 50MF8B60FVuGPcS7fc7Q2sAxaAKZaNYXK+/040qcR+k= | 2016-07-27 13:53:05 | afg2Vik+q1g5kCUcTEO9kx4zMk0tjUWHtO+AhWLYp7U= |           11 | Conflict - not sequenced |
	| info@continusec.com | 50MF8B60FVuGPcS7fc7Q2sAxaAKZaNYXK+/040qcR+k= | 2016-07-27 13:55:56 | 1r3bFYbvaSNpu1sh+fajzLz17iPq7kT7SvFbSBpTVPk= |           12 |                        6 |
	| info@continusec.com | eMV5VioXJp8O9ZmHxG08Ys4yFKOcdzy1OpOkCNNYqKk= | 2016-07-27 13:59:07 | u23v5GlfaFxxSSMnVOjoPArvchjiViKbb8kiJ+VLYXQ= |           13 |                        7 |
	| info@continusec.com | eMV5VioXJp8O9ZmHxG08Ys4yFKOcdzy1OpOkCNNYqKk= | 2016-07-27 13:59:09 | vKYGwSTW4LONNmSFjGUsf/F1PwqT7WgQVWr7z9d81jI= |           14 |                        7 |
	| info@continusec.com | eMV5VioXJp8O9ZmHxG08Ys4yFKOcdzy1OpOkCNNYqKk= | 2016-07-27 13:59:10 | wSrzXxha82hR1mC0TJc2Jn/UibPbv0jA+PjttAmkEkI= |           15 |                        7 |
	| info@continusec.com | 50MF8B60FVuGPcS7fc7Q2sAxaAKZaNYXK+/040qcR+k= | 2016-07-27 14:09:01 | PzX1d4T6nFL2T6UGMcJ/T7Ev+RKWU+SFbh5qf9uVdt4= |           16 |                        8 |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+