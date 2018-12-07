.PHONY: all build

capdef_file = ./irc/caps/defs.go

all: build

build:
	goreleaser --snapshot --rm-dist

buildrelease:
	goreleaser --skip-publish --rm-dist

capdefs:
	python3 ./gencapdefs.py > ${capdef_file}

deps:
	go get

test:
	python3 ./gencapdefs.py | diff - ${capdef_file}
	cd irc && go test . && go vet .
	cd irc/caps && go test . && go vet .
	cd irc/isupport && go test . && go vet .
	cd irc/modes && go test . && go vet .
	cd irc/passwd && go test . && go vet .
	cd irc/utils && go test . && go vet .
	./.check-gofmt.sh
