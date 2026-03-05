## build ergo binary
FROM docker.io/golang:1.26-alpine3.22 AS build-env

RUN apk upgrade -U --force-refresh --no-cache && apk add --no-cache --purge --clean-protected -l -u make git

# copy ergo source
WORKDIR /go/src/github.com/ergochat/ergo
COPY . .

# modify default config file so that it doesn't die on IPv6
# and so it can be exposed via 6667 by default
RUN sed -i 's/^\(\s*\)\"127.0.0.1:6667\":.*$/\1":6667":/' /go/src/github.com/ergochat/ergo/default.yaml && \
    sed -i 's/^\s*\"\[::1\]:6667\":.*$//' /go/src/github.com/ergochat/ergo/default.yaml

# compile
RUN make install

## build ergo container
FROM docker.io/alpine:3.22

# metadata
LABEL maintainer="Daniel Oaks <daniel@danieloaks.net>,Daniel Thamdrup <dallemon@protonmail.com>" \
      description="Ergo is a modern, experimental IRC server written in Go"

# standard ports listened on
EXPOSE 6667/tcp 6697/tcp

# ergo itself
COPY --from=build-env /go/bin/ergo \
                      /go/src/github.com/ergochat/ergo/default.yaml \
                      /go/src/github.com/ergochat/ergo/distrib/docker/run.sh \
                      /ircd-bin/
COPY --from=build-env /go/src/github.com/ergochat/ergo/languages /ircd-bin/languages/

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
