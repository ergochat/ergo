#!/bin/sh

set -e

if [ -z "$GOPATH" ]; then
	echo Error: \$GOPATH is unset
	echo See https://golang.org/doc/code.html for details, or try these steps:
	printf "\tmkdir -p ~/go\n"
	printf "\texport GOPATH=~/go\n"
	exit 1
fi

EXPECTED_DIR=${GOPATH}/src/github.com/oragono/oragono

if [ "$PWD" != "$EXPECTED_DIR" ] ; then
	echo Error: working directory is not where \$GOPATH expects it to be
	echo "Expected: $EXPECTED_DIR"
	echo "Actual:   $PWD"
	echo See https://golang.org/doc/code.html for details, or try these steps:
	printf "\tmkdir -p %s/src/github.com/oragono\n" "$GOPATH"
	printf "\tcd %s/src/github.com/oragono\n" "$GOPATH"
	printf "\tmv %s oragono\n" "$PWD"
	printf "\tcd oragono\n"
	exit 1
fi

go install -v
echo successfully installed as "${GOPATH}/bin/oragono"
