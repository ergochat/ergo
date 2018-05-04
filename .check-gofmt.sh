#!/bin/bash

# exclude vendor/
SOURCES="./oragono.go ./irc"

if [ -n "$(gofmt -s -l $SOURCES)" ]; then
    echo "Go code is not formatted correctly with \`gofmt -s\`:"
    gofmt -s -d $SOURCES
    exit 1
fi
