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

test:
	python3 ./gencapdefs.py | diff - ${capdef_file}
	go test ./...
	go vet ./...
	./.check-gofmt.sh

smoke:
	ergo mkcerts --conf ./default.yaml || true
	ergo run --conf ./default.yaml --smoke

gofmt:
	./.check-gofmt.sh --fix

irctest:
	git submodule update --init
	cd irctest && make ergo
