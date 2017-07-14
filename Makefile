BUILD=./build
WIN=$(BUILD)/win
LINUX=$(BUILD)/linux
OSX=$(BUILD)/osx
ARM6=$(BUILD)/arm
SOURCE=oragono.go
VERS=XXX

.PHONY: all clean windows osx linux arm6

add-files = mkdir -p $1; \
	cp oragono.yaml $1; \
	cp oragono.motd $1; \
	cp LICENSE $1; \
	cp ./docs/README $1; \
	mkdir -p $1/docs; \
	cp ./CHANGELOG.md $1/docs/; \
	cp ./docs/logo* $1/docs/;

all: clean windows osx linux arm6

clean:
	rm -rf $(BUILD)
	mkdir -p $(BUILD)

windows:
	GOOS=windows GOARCH=amd64 go build $(SOURCE)
	$(call add-files,$(WIN))
	mv oragono.exe $(WIN)
	cd $(WIN) && zip -r ../oragono-$(VERS)-windows.zip *

osx:
	GOOS=darwin GOARCH=amd64 go build oragono.go
	$(call add-files,$(OSX))
	mv oragono $(OSX)
	cd $(OSX) && tar -czvf ../oragono-$(VERS)-osx.tgz *

linux:
	GOOS=linux GOARCH=amd64 go build oragono.go
	$(call add-files,$(LINUX))
	mv oragono $(LINUX)
	cd $(LINUX) && tar -czvf ../oragono-$(VERS)-linux.tgz *

arm6:
	GOARM=6 GOARCH=arm go build oragono.go
	$(call add-files,$(ARM6))
	mv oragono $(ARM6)
	cd $(ARM6) && tar -czvf ../oragono-$(VERS)-arm.tgz *
