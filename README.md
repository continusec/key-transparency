# Continusec Key Server

This project contains the source code for a [CONIKS](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-melara.pdf)-inspired Key Transparency server that provides an effective demonstration of how to use the [Continusec Verifiable Data Structures API](https://www.continusec.com/) to produce a verifiable and trustworthy service.

This repository consists of two sections:

1. `cmd/cks` - The source code for a client that talks to the Key Server
2. `server` - The source code for the server itself

To read more about the REST API provided by the server, please refer to [REST-API documentation](REST-API.md).

For a detailed guide to the client, see the [Client Guide documentation](Client-Guide.md).

For information on how to run your own server, see the [Server Guide documentation](Server-Guide.md).

## What exactly is the server?

The Continusec Key Server provides a [Verifiable Map](https://www.continusec.com/product/verifiable-map) of Email addresses to PGP Public Keys with the following properties:

- Any user may add or update their own public key to this map.

- Any user may efficiently detect changes to their own key, or other keys that they are interested in.

- Any user may efficiently defend against a split-view attack by gossip of a single tree hash.

- Any interested party may fetch the current or historical public key for a known user.

- Any interested party may audit the correct operation of the map by downloading all entries, without being able to gain a directory of email addresses.

## Quickstart

Get the client, and use it to upload your public key. See [instructions here](Client-Guide.md).

# Questions / feedback?

For any questions / feedback, please open an issue in Github, or send mail to: <support@continusec.com>

The primary purpose of developing the Continusec Key Server was to provide an effective demonstration of the capabilities of the [Continusec Verifiable Data Structures API](https://www.continusec.com/).

We thank the [CONIKS](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-melara.pdf) folk for the inspiration to build this demonstration.

