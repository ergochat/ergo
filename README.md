# Ergonomadic

Ergonomadic is an IRC daemon written from scratch in Go. Pull requests
and issues are welcome.

## Some Features

- follows the RFC where possible
- gcfg gitconfig-style configuration
- server password (PASS command)
- channels with most standard modes
- IRC operators (OPER command)
- haproxy [PROXY protocol](http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt) header for hostname setting
- passwords stored in bcrypt format
- channels that persist between restarts (+P)

## Why?

I wanted to learn Go.

## What's with the name?

"Ergonomadic" is an anagram of "Go IRC Daemon".

## What about SSL/TLS support?

Go has a not-yet-verified-as-safe TLS 1.2 implementation. Sadly, many
popular IRC clients will negotiate nothing newer than SSLv2. If you
want to use SSL to protect traffic, I recommend using
[stunnel](https://www.stunnel.org/index.html) version 4.56 with
haproxy's
[PROXY protocol](http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt). This
will allow the server to get the client's original addresses for
hostname lookups.

## Installation

```sh
go get
go install
ergonomadic -conf ergonomadic.conf -initdb
```

## Configuration

See the example `ergonomadic.conf`. Passwords are base64-encoded
bcrypted byte strings. You can generate them with the `genpasswd`
subcommand.

```sh
ergonomadic -genpasswd 'hunter2!'
```

## Running the Server

```sh
ergonomadic -conf ergonomadic.conf
```

## Helpful Documentation

- [RFC 1459: Internet Relay Chat Protocol](http://tools.ietf.org/html/rfc1459)
- [RFC 2811: IRC Channel Management](http://tools.ietf.org/html/rfc2811)
- [RFC 2812: IRC Client Protocol](http://tools.ietf.org/html/rfc2812)
- [RFC 2813: IRC Server Protocol](http://tools.ietf.org/html/rfc2813)
- [IRC/2 Numeric List](https://www.alien.net.au/irc/irc2numerics.html)
