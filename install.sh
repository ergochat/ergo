#!/bin/sh

set -e

if [ -z "$GOPATH" ]; then
	echo Error: \$GOPATH is unset
	echo See https://golang.org/doc/code.html for details, or try these steps:
	echo -e "\tmkdir -p ~/go"
	echo -e "\texport GOPATH=~/go"
	exit 1
fi

EXPECTED_DIR=${GOPATH}/src/github.com/oragono/oragono

if [ "$PWD" != "$EXPECTED_DIR" ] ; then
	echo Error: working directory is not where \$GOPATH expects it to be
	echo "Expected: $EXPECTED_DIR"
	echo "Actual:   $PWD"
	echo See https://golang.org/doc/code.html for details, or try these steps:
	echo -e "\tmkdir -p ${GOPATH}/src/github.com/oragono"
	echo -e "\tcd ${GOPATH}/src/github.com/oragono"
	echo -e "\tmv $PWD oragono"
	echo -e "\tcd oragono"
	exit 1
fi

go install -v
echo successfully installed as ${GOPATH}/bin/oragono
