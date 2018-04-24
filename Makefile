.PHONY: all build

all: build

build:
	goreleaser --snapshot --rm-dist

buildrelease:
	goreleaser --skip-publish --rm-dist

deps:
	git submodule update --init

test:
	cd irc && go test . && go vet .
	cd irc/isupport && go test . && go vet .
	cd irc/modes && go test . && go vet .
	cd irc/utils && go test . && go vet .
