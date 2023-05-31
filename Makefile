.PHONY: all install build release capdefs test smoke gofmt irctest

GIT_COMMIT := $(shell git rev-parse HEAD 2> /dev/null)
GIT_TAG := $(shell git tag --points-at HEAD 2> /dev/null | head -n 1)

# disable linking against native libc / libpthread by default;
# this can be overridden by passing CGO_ENABLED=1 to make
export CGO_ENABLED ?= 0

capdef_file = ./irc/caps/defs.go

all: build

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

smoke: install
	ergo mkcerts --conf ./default.yaml || true
	ergo run --conf ./default.yaml --smoke

gofmt:
	./.check-gofmt.sh --fix

irctest: install
	git submodule update --init
	cd irctest && make ergo
