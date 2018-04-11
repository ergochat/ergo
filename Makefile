.PHONY: all build

all: build

build:
	goreleaser --snapshot --rm-dist

buildrelease:
	goreleaser --skip-publish --rm-dist

deps:
	git submodule update --init

test:
	cd irc && go test .
	cd irc && go vet .
