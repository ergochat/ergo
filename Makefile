GIT_COMMIT := $(shell git rev-parse HEAD 2> /dev/null)
GIT_TAG := $(shell git tag --points-at HEAD 2> /dev/null | head -n 1)

# disable linking against native libc / libpthread by default;
# this can be overridden by passing CGO_ENABLED=1 to make
export CGO_ENABLED ?= 0

# build tags for the maximalist build with everything included
full_tags = i18n mysql postgresql sqlite

# build everything by default; override by passing, e.g. ERGO_BUILD_TAGS="mysql postgresql"
ERGO_BUILD_TAGS ?= $(full_tags)

capdef_file = ./irc/caps/defs.go

.PHONY: all
all: build

.PHONY: build
build:
	go build -v -tags "$(ERGO_BUILD_TAGS)" -ldflags "-X main.commit=$(GIT_COMMIT) -X main.version=$(GIT_TAG)"

.PHONY: install
install:
	go install -v -tags "$(ERGO_BUILD_TAGS)" -ldflags "-X main.commit=$(GIT_COMMIT) -X main.version=$(GIT_TAG)"

.PHONY: release
release:
	goreleaser --skip=publish --clean

.PHONY: minimal
minimal:
	go build -v -tags "" -ldflags "-X main.commit=$(GIT_COMMIT) -X main.version=$(GIT_TAG)"

.PHONY: capdefs
capdefs:
	python3 ./gencapdefs.py > ${capdef_file}

.PHONY: test
test:
	python3 ./gencapdefs.py | diff - ${capdef_file}
	go test -tags "$(full_tags)" ./...
	go vet -tags "$(full_tags)" ./...
	go vet -tags "" ./...
	./.check-gofmt.sh

.PHONY: smoke
smoke: install
	ergo mkcerts --conf ./default.yaml || true
	ergo run --conf ./default.yaml --smoke

.PHONY: gofmt
gofmt:
	./.check-gofmt.sh --fix

.PHONY: irctest
irctest: install
	git submodule update --init
	cd irctest && make ergo
