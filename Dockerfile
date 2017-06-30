FROM golang:alpine

EXPOSE 6667/tcp 6697/tcp 8080/tcp

RUN \
    apk add --update git && \
    rm -rf /var/cache/apk/*

RUN mkdir -p /go/src/github.com/oragono/oragono
WORKDIR /go/src/github.com/oragono/oragono

COPY . /go/src/github.com/oragono/oragono

RUN go get -v -d
RUN go build .

CMD ["./run.sh"]
