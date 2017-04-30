![Oragono logo](docs/logo.png)

Oragono is a modern, experimental IRC server written in Go. It's designed to be simple to setup and use, and it includes features such as UTF-8 nicks / channel names, client accounts with SASL, and other assorted IRCv3 support.

Oragono is a fork of the [Ergonomadic](https://github.com/edmund-huber/ergonomadic) IRC daemon <3

---

[![Go Report Card](https://goreportcard.com/badge/github.com/DanielOaks/oragono)](https://goreportcard.com/report/github.com/DanielOaks/oragono)
[![Download Latest Release](https://img.shields.io/badge/downloads-latest%20release-green.svg)](https://github.com/DanielOaks/oragono/releases/latest)
[![Freenode #oragono](https://img.shields.io/badge/Freenode-%23oragono-1e72ff.svg?style=flat)](https://www.irccloud.com/invite?channel=%23oragono&hostname=irc.freenode.net&port=6697&ssl=1)

---

This project adheres to [Semantic Versioning](http://semver.org/). For the purposes of versioning, we consider the "public API" to refer to the configuration files, CLI interface and database format.

# Oragono

## Features

* UTF-8 nick and channel names with rfc7613
* [yaml](http://yaml.org/) configuration
* native TLS/SSL support
* server password (`PASS` command)
* an extensible privilege system for IRC operators
* ident lookups for usernames
* automated client connection limits
* on-the-fly updating server config and TLS certificates (rehashing)
* client accounts and SASL
* passwords stored with [bcrypt](https://godoc.org/golang.org/x/crypto) (client account passwords also salted)
* banning ips/nets and masks with `KLINE` and `DLINE`
* [IRCv3 support](http://ircv3.net/software/servers.html)
* a heavy focus on developing with [specifications](http://oragono.io/specs.html)
* integrated (alpha) REST API and web interface

## Installation

Download the latest release from this page: https://github.com/DanielOaks/oragono/releases/latest

Extract it into a folder, then run the following commands:

```sh
cp oragono.yaml ircd.yaml
vim ircd.yaml  # modify the config file to your liking
oragono initdb
oragono mkcerts
```

**Note:** This installation will give you unsigned certificates suitable for testing purposes.
For real crets, look into [Let's Encrypt](https://letsencrypt.org/)!

## Configuration

The default config file [`oragono.yaml`](oragono.yaml) helps walk you through what each option means and changes. The configuration's intended to be sparse, so if there are options missing it's either because that feature isn't written/configurable yet or because we don't think it should be configurable.

### Logs

By default, logs are stored in the file `ircd.log`. The configuration format of logs is designed to be easily pluggable, and is inspired by the logging config provided by InspIRCd.

### Passwords

Passwords (for both `PASS` and oper logins) are stored using bcrypt. To generate encrypted strings for use in the config, use the `genpasswd` subcommand as such:

```sh
oragono genpasswd
```

With this, you receive a blob of text which you can plug into your configuration file.

## Running

After this, running the server is easy! Simply run the below command and you should see the relevant startup information pop up.

```sh
oragono run
```

<!--# Web interface

Oragono also includes a web interface, which works with the REST API to provide a way to manage user accounts and bans.

This interface is an early alpha, is in no way secure and will not be in a final release for a while. Requires the alpha REST API to be enabled (check your server config to enable that if you really want to).

## Installation

```sh
go build oragono-web.go
cp oragono-web.yaml web.yaml
vim web.yaml  # modify the config file to your liking
oragono-web mkcerts
```

## Running

```sh
oragono-web run
```-->

# Credits

* Jeremy Latt, creator of Ergonomadic, <https://github.com/jlatt>
* Edmund Huber, maintainer of Ergonomadic, <https://github.com/edmund-huber>
* Niels Freier, added WebSocket support to Ergonomadic, <https://github.com/stumpyfr>
* Daniel Oakley, maintainer of Oragono, <https://github.com/DanielOaks>
* apologies to anyone I forgot.
