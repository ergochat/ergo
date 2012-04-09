#!/bin/bash
set -ex
export GOPATH="$(pwd)"
go install irc
go run ergonomadic.go
