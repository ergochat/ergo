# Ergonomadic

Ergonomadic is an IRC daemon written from scratch in Go.

## Some Features

- follows the RFC where possible
- JSON-based configuration
- server password
- channels with many standard modes
- IRC operators
- TLS support (but better to use stunnel with proxy protocol)
- haproxy PROXY protocol header for hostname setting
- passwords stored in bcrypt format

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

See the example `config.json`. Passwords are base64-encoded bcrypted
byte strings. You can generate them with e.g. `ergonomadic -genpasswd
'hunter21!'`.

### from your GOPATH

```sh
go get
go install
ergonomadic -conf '/path/to/ergonomadic.json'
```
