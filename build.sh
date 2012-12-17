#!/bin/bash
export GOPATH="$PWD"
go get "code.google.com/p/go.crypto/bcrypt"
go install ergonomadic genpasswd
