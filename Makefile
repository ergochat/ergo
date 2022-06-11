.PHONY: all install build release capdefs test smoke gofmt irctest

GIT_COMMIT := $(shell git rev-parse HEAD 2> /dev/null)
GIT_TAG := $(shell git tag --points-at HEAD 2> /dev/null | head -n 1)

capdef_file = ./irc/caps/defs.go

all: install

install:
	go install -v -ldflags "-X main.commit=$(GIT_COMMIT) -X main.version=$(GIT_TAG)"

build:
	go build -v -ldflags "-X main.commit=$(GIT_COMMIT) -X main.version=$(GIT_TAG)"

release:
	goreleaser --skip-publish --rm-dist

capdefs:
	python3 ./gencapdefs.py > ${capdef_file}

test: test-capdefs test-irc test-caps test-cloaks test-connection_limits test-email test-flatip test-history test-isupport test-migrations test-modes test-mysql test-passwd test-sno test-utils test-gofmt

test-capdefs:
	python3 ./gencapdefs.py | diff - ${capdef_file}

test-gofmt:
	./.check-gofmt.sh

test-irc:
	cd irc && go test . && go vet .

test-%:
	cd irc/$(patsubst test-%,%,$@) && go test . && go vet .

smoke:
	ergo mkcerts --conf ./default.yaml || true
	ergo run --conf ./default.yaml --smoke

gofmt:
	./.check-gofmt.sh --fix

irctest:
	git submodule update --init
	cd irctest && make ergo
