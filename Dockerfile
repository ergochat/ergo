# syntax=docker/dockerfile:latest@sha256:ac85f380a63b13dfcefa89046420e1781752bab202122f8f50032edf31be0021
## build ergo binary
FROM cgr.dev/chainguard/go:latest@sha256:c894bc454800817b1747c8a1a640ae6d86004b06190f94e791098e7e78dbbc00 AS build-env

# copy ergo source
WORKDIR /go/src/github.com/ergochat/ergo
COPY . .

# modify default config file so that it doesn't die on IPv6
# and so it can be exposed via 6667 by default
RUN sed -i 's/^\(\s*\)\"127.0.0.1:6667\":.*$/\1":6667":/' /go/src/github.com/ergochat/ergo/default.yaml && \
    sed -i 's/^\s*\"\[::1\]:6667\":.*$//' /go/src/github.com/ergochat/ergo/default.yaml

# compile
RUN make install

## tmp container for collecting files
FROM scratch AS tmp

# collect all files
COPY --from=build-env /root/go/bin/ergo \
                      /go/src/github.com/ergochat/ergo/default.yaml \
                      /go/src/github.com/ergochat/ergo/distrib/docker/run.sh \
                      /ircd-bin/
COPY --from=build-env /go/src/github.com/ergochat/ergo/languages /ircd-bin/languages/
COPY --from=build-env /go/src/github.com/ergochat/ergo/ergo.motd /ircd/ergo.motd

## build ergo container
FROM cgr.dev/chainguard/busybox:latest-glibc@sha256:f5f11a14dda5355dff116219302d45f1a4fd018285c8922cf848a9b24cae1f3d AS runtime

# metadata
LABEL maintainer="Daniel Oaks <daniel@danieloaks.net>,Daniel Thamdrup <danielthamdrup@pm.me>" \
      description="Ergo is a modern, experimental IRC server written in Go"

# standard ports listened on
EXPOSE 6667/tcp 6697/tcp

# ergo itself
COPY --from=tmp --chown=nonroot:nonroot / /

# running volume holding config file, db, certs
VOLUME /ircd
WORKDIR /ircd

# launch
ENTRYPOINT ["/ircd-bin/run.sh"]
