## build Ergo
FROM golang:1.16-alpine AS build-env

RUN apk add --no-cache git make curl sed

# copy ergo
RUN mkdir -p /go/src/github.com/ergochat/ergo
WORKDIR /go/src/github.com/ergochat/ergo
ADD . /go/src/github.com/ergochat/ergo/

# modify default config file so that it doesn't die on IPv6
# and so it can be exposed via 6667 by default
run sed -i 's/^\(\s*\)\"127.0.0.1:6667\":.*$/\1":6667":/' /go/src/github.com/ergochat/ergo/default.yaml
run sed -i 's/^\s*\"\[::1\]:6667\":.*$//' /go/src/github.com/ergochat/ergo/default.yaml

# compile
RUN make



## run Ergo
FROM alpine:3.9

# metadata
LABEL maintainer="daniel@danieloaks.net"
LABEL description="Ergo is a modern, experimental IRC server written in Go"

# install latest updates and configure alpine
RUN apk update
RUN apk upgrade
RUN mkdir /lib/modules

# standard ports listened on
EXPOSE 6667/tcp 6697/tcp

# oragono itself
RUN mkdir -p /ircd-bin
COPY --from=build-env /go/bin/ergo /ircd-bin
COPY --from=build-env /go/src/github.com/ergochat/ergo/languages /ircd-bin/languages/
COPY --from=build-env /go/src/github.com/ergochat/ergo/default.yaml /ircd-bin/default.yaml

COPY distrib/docker/run.sh /ircd-bin/run.sh
RUN chmod +x /ircd-bin/run.sh

# running volume holding config file, db, certs
VOLUME /ircd
WORKDIR /ircd

# default motd
COPY --from=build-env /go/src/github.com/ergochat/ergo/ergo.motd /ircd/ergo.motd

# launch
ENTRYPOINT ["/ircd-bin/run.sh"]

# # uncomment to debug
# RUN apk add --no-cache bash
# RUN apk add --no-cache vim
# CMD /bin/bash
