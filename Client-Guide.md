# Continusec Key Server Client

This directory contains a client for the Continusec Key Server. See <https://github.com/continusec/key-transparency> for the source code for the server component.

## License

The Continusec Key Server Client is distributed under the Apache 2 License.

## Installation

The client is written in Go, begin by installing the Go compiler from: <https://golang.org/doc/install>.

Once installed, install the client:

    go get github.com/continusec/key-transparency/cmd/cks

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
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/treehead/tree/1/inclusion/h/26e9bd9ddc8c362224fb8d6c62c16cc4c95875647e19ff93debded6deb236630
	Initialization complete.

## Tracking Server State

A new Continusec Key Server begins at sequence 0 which increases over time as entries are modified. The client keeps track of what sequence number is currently in effect.

To see the current sequence number in effect:

    cks status

Results in:

    Tracking revision: 1

To check for updates from the server use:

    cks update

Which shows any requests sent to the server for fresh state, and completes by displaying the revision in effect (in this case, unchanged):

	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0
	Tracking revision: 1

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

	eyJzaWciOiJNRVFDSUMwVWlJZUNqWElpd25wWVJTTys4YnFwSTZIZzczTTBSWVRpSnFiclJ0Y2VBaUJnNml2UnRHNC94b2F2U0l0ZEVIb1AzR05CaTdFTE1YRDdMQVlvTFV2bDJnPT0iLCJ0aGx0aCI6ImV5SjBjbVZsWDNOcGVtVWlPakVzSW5SeVpXVmZhR0Z6YUNJNklrcDFiVGx1WkhsTlRtbEpheXMwTVhOWmMwWnplRTFzV1dSWFVpdEhaaXRVTTNJemRHSmxjMnBhYWtFOUluMEsifQo=
    
If you base-64 decode this, we get:

	{
	    "sig": "MEQCIC0UiIeCjXIiwnpYRSO+8bqpI6Hg73M0RYTiJqbrRtceAiBg6ivRtG4/xoavSItdEHoP3GNBi7ELMXD7LAYoLUvl2g==",
	    "thlth": "eyJ0cmVlX3NpemUiOjEsInRyZWVfaGFzaCI6Ikp1bTluZHlNTmlJays0MXNZc0ZzeE1sWWRXUitHZitUM3IzdGJlc2paakE9In0K"
	}


The `thlth` field is base-64 encoded JSON as received by the client for the latest tree head log tree head for the map and the `sig` field is the base-64 encoded ASN.1 signature over the JSON bytes as returned by the Key Server.

If two inconsistent `thlth` values are emitted by the Key Server, that is a sign of misbehavior.

## Uploading your own public key

To upload your own public key, either new or as an update, first request an authorization token be sent to your email address, for example:

    cks mail info@continusec.com

Type `yes` to continue:

    Are you sure you want to generate and send a token to address (info@continusec.com)? Please only do so if you own that email account. Type yes or no to continue: yes

And upon success:

	Sending mail to info@continusec.com with token...
	Success. See email for further instructions.

Wait for an email including the token, and then use this to upload your key, which can should be the output of `gpg --armor --export`. Either pipe this as follows:

    gpg --armor --export info@continusec.com | cks upload info@continusec.com - ME0wRQIge+mIyeT/eJjZyh+FeB4NWdxn23a5eD8d8K23ZTeetsMCIQDl9Ye7bXvfP6sNbzjpn9v6UrKipxwdeHYN3698W5YN+gIEV5r3Jw==
    
Or save in a file, and repalce the `-` with the filename. Result:

	Setting key for info@continusec.com with token...
	Success. Leaf hash of mutation: 9y1sTCXsI/1sGCB6jEq1629fNHbYEqFwVWrJlmpLk5w=

Done, your key has been added to the key server.

To see the status of update key requests:

	cks log

Will show a table of updates:

	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+-------------------+---------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              |   MAP SEQUENCE    | USER SEQUENCE |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+-------------------+---------------+
	| info@continusec.com | mGng5V2kf9NREaeOke3bAaMJLHOgAa4YulFgisVErcI= | 2016-07-29 15:28:19 | 9y1sTCXsI/1sGCB6jEq1629fNHbYEqFwVWrJlmpLk5w= | Not yet sequenced |               |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+-------------------+---------------+

To refresh this table and display the log again:

    cks update && cks log

Result:

	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/2/consistency/1
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/treehead/tree/0
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/treehead/tree/2/consistency/1
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/treehead/tree/2/inclusion/h/623c4ebd680004167341c4e713418f86f89521d5e61528edb34708059a3e8c03
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/2/inclusion/h/f72d6c4c25ec23fd6c18207a8c4ab5eb6f5f3476d812a170556ac9966a4b939c
	Fetching: https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com/at/2
	Tracking revision: 2
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+---------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              | MAP SEQUENCE | USER SEQUENCE |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+---------------+
	| info@continusec.com | mGng5V2kf9NREaeOke3bAaMJLHOgAa4YulFgisVErcI= | 2016-07-29 15:28:19 | 9y1sTCXsI/1sGCB6jEq1629fNHbYEqFwVWrJlmpLk5w= |            1 |             0 |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+---------------+

`Not yet sequenced` means that the mutation log entry has not yet been sequenced and added to the map. Once it has been sequenced (that is a number appears in this column), then any revision of the map *greater than* that number will reflect this value. So here mutation 1 is reflected in map sequence number 2 and beyond.

The `User sequence` column shows an increasing sequence number for just this user. The initial value for each user is 0 and this increases with each successful update. If a fresh update is requested for a user while another update is pending to apply, it will result in a `Conflict - not sequenced` message like below:

	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              | MAP SEQUENCE |      USER SEQUENCE       |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	| info@continusec.com | mGng5V2kf9NREaeOke3bAaMJLHOgAa4YulFgisVErcI= | 2016-07-29 15:28:19 | 9y1sTCXsI/1sGCB6jEq1629fNHbYEqFwVWrJlmpLk5w= |            1 |                        0 |
	| info@continusec.com | or/a9EtFEwy+sdGs53Jv/6+gmCtOAcTMFXXlsOWKKRc= | 2016-07-29 15:33:09 | 1PgRupcjard1bpHd2aYHckq1XTKBDoS5P2n9jQ8EEM0= |            2 |                        1 |
	| info@continusec.com | 995GpJzmXOa8RQ3TAQNtzJfwtv3gJdOsPIqVpYml4AA= | 2016-07-29 15:33:13 | O9oFUxckh7pemYLywENdZup6QIkwIQFv0RmHfudhwCI= |            3 | Conflict - not sequenced |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+


This occurs as each update request is conditional on a previous value - here the previous value (map sequence number 2) was not yet available when map sequence 3 was requested, and as such the update for 3 did not have the expected previous value and thus it was never applied to the map. In such a case you can simply try again:

	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	|        EMAIL        |                  VALUE HASH                  |      TIMESTAMP      |              MUTATION LOG ENTRY              | MAP SEQUENCE |      USER SEQUENCE       |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+
	| info@continusec.com | mGng5V2kf9NREaeOke3bAaMJLHOgAa4YulFgisVErcI= | 2016-07-29 15:28:19 | 9y1sTCXsI/1sGCB6jEq1629fNHbYEqFwVWrJlmpLk5w= |            1 |                        0 |
	| info@continusec.com | or/a9EtFEwy+sdGs53Jv/6+gmCtOAcTMFXXlsOWKKRc= | 2016-07-29 15:33:09 | 1PgRupcjard1bpHd2aYHckq1XTKBDoS5P2n9jQ8EEM0= |            2 |                        1 |
	| info@continusec.com | 995GpJzmXOa8RQ3TAQNtzJfwtv3gJdOsPIqVpYml4AA= | 2016-07-29 15:33:13 | O9oFUxckh7pemYLywENdZup6QIkwIQFv0RmHfudhwCI= |            3 | Conflict - not sequenced |
	| info@continusec.com | 995GpJzmXOa8RQ3TAQNtzJfwtv3gJdOsPIqVpYml4AA= | 2016-07-29 15:34:40 | 6BE4IhuPxv3RZ6RsdSVP0zVzhvhkuxSKJF0TwHrIBhA= |            4 |                        2 |
	+---------------------+----------------------------------------------+---------------------+----------------------------------------------+--------------+--------------------------+

It is also possible to see multiple entries with the same `Value Hash` and `User Sequence` - this occurs if duplicate requests arrive at once. Technically only one of the mutation operation actually takes effect, however for the purpose of the console report we simply show th same user sequence against each, signifying that that value hash was in effect at that map mutation size.
	
## Watching other users (their keys)

To indicate interest in watching the key that belongs to another user, run this command:

	cks follow info@continusec.com

Result:

	Following info@continusec.com.

Then run:

   cks list
   
To see the status of all keys followed:

	+---------------------+------------+---------------+--------------+
	|        EMAIL        | VALUE HASH | USER SEQUENCE | LAST UPDATED |
	+---------------------+------------+---------------+--------------+
	| info@continusec.com | (none)     | No key found  | Never        |
	+---------------------+------------+---------------+--------------+

To update, run:

    cks update && cks list

Result:

	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0
	Tracking revision: 5
	+---------------------+----------------------------------------------+---------------+--------------+
	|        EMAIL        |                  VALUE HASH                  | USER SEQUENCE | LAST UPDATED |
	+---------------------+----------------------------------------------+---------------+--------------+
	| info@continusec.com | 995GpJzmXOa8RQ3TAQNtzJfwtv3gJdOsPIqVpYml4AA= |             2 |            5 |
	+---------------------+----------------------------------------------+---------------+--------------+

Like before, `User Sequence` is an incrmenting index per-user of key changes. `Last Updated` is the size of the map when this was last checked, and should match the number shown by `cks status`.

Let's follow some more users and show what happens if no key is found:

    cks follow support@continusec.com foo@bar.com user@host.com

Result:

	Following support@continusec.com.
	Following foo@bar.com.
	Following user@host.com.

Now:

    cks update && cks list

Gives:

	+------------------------+----------------------------------------------+---------------+--------------+
	|         EMAIL          |                  VALUE HASH                  | USER SEQUENCE | LAST UPDATED |
	+------------------------+----------------------------------------------+---------------+--------------+
	| foo@bar.com            | (none)                                       | No key found  |            5 |
	| info@continusec.com    | 995GpJzmXOa8RQ3TAQNtzJfwtv3gJdOsPIqVpYml4AA= |             2 |            5 |
	| support@continusec.com | (none)                                       | No key found  |            5 |
	| user@host.com          | (none)                                       | No key found  |            5 |
	+------------------------+----------------------------------------------+---------------+--------------+

Note that we can use `cks update <number>` to get a previous view in time:

    cks update 2 && cks list //TODO got up to here. fix bug where this fails due to arg check in cks status

Gives:

	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/10
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/10/consistency/1
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/treehead/tree/19/inclusion/h/c42b648d2d573f5b6b127a9ce13e1b52bc8feedc312cae6137aed7b488b88315
	Fetching: https://continusec-key-server.appspot.com/v1/publicKey/foo@bar.com/at/10
	Fetching: https://continusec-key-server.appspot.com/v1/publicKey/info@continusec.com/at/10
	Fetching: https://continusec-key-server.appspot.com/v1/publicKey/support@continusec.com/at/10
	Fetching: https://continusec-key-server.appspot.com/v1/publicKey/user@host.com/at/10
	Tracking revision: 10
	+------------------------+----------------------------------------------+---------------+--------------+
	|         EMAIL          |                  VALUE HASH                  | USER SEQUENCE | LAST UPDATED |
	+------------------------+----------------------------------------------+---------------+--------------+
	| foo@bar.com            | (none)                                       | No key found  |           10 |
	| info@continusec.com    | kvTHQZMQ1JOGTl7m/lHVWKfIzjdDoLBsQKMKl6bppXA= |             4 |           10 |
	| support@continusec.com | (none)                                       | No key found  |           10 |
	| user@host.com          | (none)                                       | No key found  |           10 |
	+------------------------+----------------------------------------------+---------------+--------------+

And no number brings us back to the future:

	cks update
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/tree/0
	Fetching: https://continusec-key-server.appspot.com/v1/wrappedMap/log/mutation/tree/19/consistency/10
	Tracking revision: 19
	
To see the history for a user (going back from the current value):

    cks history info@continusec.com
    
Result:

	+---------------------+----------------------------------------------+---------------+-----------------------+
	|        EMAIL        |                  VALUE HASH                  | USER SEQUENCE | MAP SIZE RETRIEVED AT |
	+---------------------+----------------------------------------------+---------------+-----------------------+
	| info@continusec.com | 50MF8B60FVuGPcS7fc7Q2sAxaAKZaNYXK+/040qcR+k= |             8 |                    19 |
	| info@continusec.com | eMV5VioXJp8O9ZmHxG08Ys4yFKOcdzy1OpOkCNNYqKk= |             7 |                    16 |
	| info@continusec.com | 50MF8B60FVuGPcS7fc7Q2sAxaAKZaNYXK+/040qcR+k= |             6 |                    13 |
	| info@continusec.com | eMV5VioXJp8O9ZmHxG08Ys4yFKOcdzy1OpOkCNNYqKk= |             5 |                    12 |
	| info@continusec.com | kvTHQZMQ1JOGTl7m/lHVWKfIzjdDoLBsQKMKl6bppXA= |             4 |                    10 |
	| info@continusec.com | FaQhQAWqKUPLSJnuM1oEFgOU3o7NM0nn6R6j+wt2DJc= |             3 |                     9 |
	| info@continusec.com | vaZavgQqsBO2lerkknfBeKieJpbyH1skixbbWhj8+o8= |             2 |                     8 |
	| info@continusec.com | wIL2fy/RF/7T6LH+sKPsjgq2nTSD8sFjuywnSI6P79E= |             1 |                     7 |
	| info@continusec.com | YQ4kbkLQn9NbSrohth0QH7Uh/Mv3NIE50Wzz5GD3hGo= |             0 |                     6 |
	+---------------------+----------------------------------------------+---------------+-----------------------+

To export a key for a user for the current map state in effect:

    cks export info@continusec.com
 
Result:
 
    <binary data>

To export a specific sequence number (user sequence):

    cks export info@continusec.com/3

Result:
 
    <binary data>

# Questions / feedback?

For any questions / feedback, please open an issue in Github, or send mail to: <support@continusec.com>

The primary purpose of developing the Continusec Key Server was to provide an effective demonstration of the capabilities of the [Continusec Verifiable Data Structures API](https://www.continusec.com/).

We thank the [CONIKS](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-melara.pdf) folk for the inspiration to build this demonstration.

