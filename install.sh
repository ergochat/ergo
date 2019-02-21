#!/bin/bash

set -e

if [ -z "$GOPATH" ]; then
	echo \$GOPATH is unset: see https://golang.org/doc/code.html for details
	exit 1
fi

EXPECTED_DIR=${GOPATH}/src/github.com/oragono/oragono

if [ `pwd` != "$EXPECTED_DIR" ] ; then
	echo working checkout is not where \$GOPATH expects it: should be $EXPECTED_DIR
	exit 1
fi

go install -v
echo successfully installed as ${GOPATH}/bin/oragono
