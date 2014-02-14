# Ergonomadic

Ergonomadic is an IRC daemon written from scratch in Go. It supports (or will)
multiple concurrent connections for the same nick.

## Why?

I wanted to learn Go.

## What's with the name?

"Ergonomadic" is an anagram of "Go IRC Daemon".

## Helpful Documentation

- [RFC 1459: Internet Relay Chat Protocol](http://tools.ietf.org/html/rfc1459)
- [RFC 2811: IRC Channel Management](http://tools.ietf.org/html/rfc2811)
- [RFC 2812: IRC Client Protocol](http://tools.ietf.org/html/rfc2812)
- [RFC 2813: IRC Server Protocol](http://tools.ietf.org/html/rfc2813)
- [IRC/2 Numeric List](https://www.alien.net.au/irc/irc2numerics.html)

## Running the Server

You must create an `ergonomadic.json` config file in the current directory.

### from your GOPATH

```sh
go install
ergonomadic
```

### from local
```sh
go run ergonomadic.go
```
