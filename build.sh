#!/usr/bin/env bash
# release build script
# to be run inside the Oragono dir

## windows ##
rm -rf ./build/win/
mkdir -p ./build/win/docs/

GOOS=windows GOARCH=amd64 go build oragono.go
mv oragono.exe ./build/win/

cp LICENSE ./build/win/
cp oragono.yaml oragono.motd ./build/win
cp ./docs/README ./build/win/
cp ./CHANGELOG.md ./build/win/docs
cp ./docs/logo* ./build/win/docs

pushd ./build/win
zip -r ../oragono-XXX-windows.zip *
popd

## osx ##
rm -rf ./build/osx/
mkdir -p ./build/osx/docs/

GOOS=darwin GOARCH=amd64 go build oragono.go
mv oragono ./build/osx/

cp LICENSE ./build/osx/
cp oragono.yaml oragono.motd ./build/osx
cp ./docs/README ./build/osx/
cp ./CHANGELOG.md ./build/osx/docs
cp ./docs/logo* ./build/osx/docs

pushd ./build/osx
tar -czvf ../oragono-XXX-osx.tgz *
popd

## linux ##
rm -rf ./build/linux
mkdir -p ./build/linux/docs/

GOOS=linux GOARCH=amd64 go build oragono.go
mv oragono ./build/linux/

cp LICENSE ./build/linux/
cp oragono.yaml oragono.motd ./build/linux
cp ./docs/README ./build/linux/
cp ./CHANGELOG.md ./build/linux/docs
cp ./docs/logo* ./build/linux/docs

pushd ./build/linux
tar -czvf ../oragono-XXX-linux.tgz *
popd

## arm ##
rm -rf ./build/arm
mkdir -p ./build/arm/docs/

GOARM=6 GOARCH=arm go build oragono.go
mv oragono ./build/arm/

cp LICENSE ./build/arm/
cp oragono.yaml oragono.motd ./build/arm
cp ./docs/README ./build/arm/
cp ./CHANGELOG.md ./build/arm/docs
cp ./docs/logo* ./build/arm/docs

pushd ./build/arm
tar -czvf ../oragono-XXX-arm.tgz *
popd
