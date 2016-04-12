Ergonomadic (anagram of "go IRC daemon") is an IRC daemon written from scratch
in Go. Pull requests and issues are welcome.

Discussion at:
* host/port: irc.skub.club:6697, use SSL
* password: smellyoulater
* #darwin

# Features

* follows the RFCs where possible
* UTF-8 nick and channel names
* [yaml](http://yaml.org/) configuration
* server password (PASS command)
* channels with most standard modes
* IRC operators (OPER command)
* haproxy [PROXY protocol][proxy-proto] header for hostname setting
* passwords stored in [bcrypt][go-crypto] format
* channels that [persist][go-sqlite] between restarts (+P)
* messages are queued in the same order to all connected clients

# What about SSL/TLS support?

Go has a not-yet-verified-as-safe TLS 1.2 implementation. Sadly, many popular
IRC clients will negotiate nothing newer than SSLv2. If you want to use SSL to
protect traffic, I recommend using
[stunnel](https://www.stunnel.org/index.html) version 4.56 with haproxy's
[PROXY protocol][proxy-proto]. This will allow the server to get the client's
original addresses for hostname lookups.

# What about federation?

IRC federation solves a problem that was more likely to occur on the internet of
1991 than today. We are exploring alternatives to federation that avoid nickname
and channel sync issues created during netsplits.

# Installation

```sh
go get
go install
cp ergonomadic.yaml ircd.yaml
vim ircd.yaml  # modify the config file to your liking
ergonomadic initdb
```

# Configuration

See the example [`ergonomadic.yaml`](ergonomadic.yaml). Passwords are base64-encoded bcrypted byte
strings. You can generate them with the `genpasswd` subcommand.

```sh
ergonomadic genpasswd
```

# Running the server

```sh
ergonomadic run
```

# Credits

* Jeremy Latt, creator, <https://github.com/jlatt>
* Edmund Huber, maintainer, <https://github.com/edmund-huber>
* Niels Freier, added WebSocket support, <https://github.com/stumpyfr>
* apologies to anyone I forgot.

[go-crypto]: https://godoc.org/golang.org/x/crypto
[go-sqlite]: https://github.com/mattn/go-sqlite3
[proxy-proto]: http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt
