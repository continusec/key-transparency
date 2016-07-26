#!/bin/sh

GOPATH=$PWD:$PWD/vendor goimports -w src/*.go
