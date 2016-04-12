Oragono is a very early, extremely experimental fork of the [Ergonomadic](https://github.com/edmund-huber/ergonomadic) IRC daemon. Ergonomadic looks cool, and this is something I can experiment on. Hopefully most of the stuff I do in this can be merged back into Ergonomadic! Also see the [mammon](https://github.com/mammon-ircd/mammon) IRC daemon for something similar written in Python.

# Features

* UTF-8 nick and channel names
* [yaml](http://yaml.org/) configuration
* server password (PASS command)
* channels with most standard modes
* IRC operators (OPER command)
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

# Installation

```sh
go get
go install
cp oragono.yaml ircd.yaml
vim ircd.yaml  # modify the config file to your liking
oragono initdb
```

# Configuration

See the example [`oragono.yaml`](oragono.yaml). Passwords are base64-encoded bcrypted byte
strings. You can generate them with the `genpasswd` subcommand.

```sh
oragono genpasswd
```

# Running the server

```sh
oragono run
```

# Credits

* Jeremy Latt, creator of Ergonomadic, <https://github.com/jlatt>
* Edmund Huber, maintainer of Ergonomadic, <https://github.com/edmund-huber>
* Niels Freier, added WebSocket support to Ergonomadic, <https://github.com/stumpyfr>
* apologies to anyone I forgot.

[go-crypto]: https://godoc.org/golang.org/x/crypto
[go-sqlite]: https://github.com/mattn/go-sqlite3
