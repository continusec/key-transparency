#!/bin/sh

GOPATH=$PWD:$PWD/vendor goimports -w src/cksserver/*.go
