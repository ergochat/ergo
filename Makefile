.PHONY: all clean build

all: clean build

clean:
	rm -rf $(BUILD)
	mkdir -p $(BUILD)

build:
	goreleaser --snapshot --rm-dist

test:
	cd irc && go test .
	cd irc && go vet .
