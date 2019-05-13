.PHONY: all install release capdefs deps test

capdef_file = ./irc/caps/defs.go

all: install

install: deps
	./install.sh

release:
	goreleaser --skip-publish --rm-dist

capdefs:
	python3 ./gencapdefs.py > ${capdef_file}

deps:
	git submodule update --init

test:
	python3 ./gencapdefs.py | diff - ${capdef_file}
	cd irc && go test . && go vet .
	cd irc/caps && go test . && go vet .
	cd irc/cloaks && go test . && go vet .
	cd irc/connection_limits && go test . && go vet .
	cd irc/history && go test . && go vet .
	cd irc/isupport && go test . && go vet .
	cd irc/modes && go test . && go vet .
	cd irc/passwd && go test . && go vet .
	cd irc/utils && go test . && go vet .
	./.check-gofmt.sh
