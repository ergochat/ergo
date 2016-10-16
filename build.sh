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
cp ./docs/CHANGELOG.md ./build/win/
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
cp ./docs/CHANGELOG.md ./build/osx/
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
cp ./docs/CHANGELOG.md ./build/linux/
cp ./docs/logo* ./build/linux/docs

pushd ./build/linux
tar -czvf ../oragono-XXX-linux.tgz *
popd
