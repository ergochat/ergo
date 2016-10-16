#!/usr/bin/env sh
# release build script
# to be run inside the Oragono dir

## windows ##
rm -rf ./build/win/
mkdir -p ./build/win/docs/

GOOS=windows GOATCH=amd64 go build oragono.go
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

GOOS=darwin GOATCH=amd64 go build oragono.go
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

GOOS=linux GOATCH=amd64 go build oragono.go
mv oragono ./build/linux/

cp LICENSE ./build/linux/
cp oragono.yaml oragono.motd ./build/linux
cp ./docs/README ./build/linux/
cp ./CHANGELOG.md ./build/linux/docs
cp ./docs/logo* ./build/linux/docs

pushd ./build/linux
tar -czvf ../oragono-XXX-linux.tgz *
popd
