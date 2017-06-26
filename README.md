![Oragono logo](docs/logo.png)

Oragono is a modern, experimental IRC server written in Go. It's designed to be simple to setup and use, and it includes features such as UTF-8 nicks / channel names, client accounts with SASL, and other assorted IRCv3 support.

Oragono is a fork of the [Ergonomadic](https://github.com/edmund-huber/ergonomadic) IRC daemon <3

---

[![Go Report Card](https://goreportcard.com/badge/github.com/oragono/oragono)](https://goreportcard.com/report/github.com/oragono/oragono)
[![Download Latest Release](https://img.shields.io/badge/downloads-latest%20release-green.svg)](https://github.com/oragono/oragono/releases/latest)
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

Download the latest release from this page: https://github.com/oragono/oragono/releases/latest

Extract it into a folder, then run the following commands:

```sh
cp oragono.yaml ircd.yaml
vim ircd.yaml  # modify the config file to your liking
oragono initdb
oragono mkcerts
```

**Note:** This installation will give you unsigned certificates suitable for testing purposes.
For real certs, look into [Let's Encrypt](https://letsencrypt.org/)!

### Platform Packaging

Some platforms may support a packaged/installation medium via a normal process for the platform. They are listed here:

| Platform | Link | Maintainer(s) |
| --- | --- | --- |
| Arch Linux | [AUR](https://aur.archlinux.org/packages/oragono/) | [Sean Enck (enckse)](https://github.com/enckse) |

### From Source

You can also install this repo and use that instead! However, keep some things in mind if you go that way:

`devel` branches are intentionally unstable, containing fixes that may not work, and they may be rebased or reworked extensively.

The `master` branch _should_ usually be stable, but may contain database changes that either have not been finalised or not had database upgrade code written yet. Don't run `master` on a live production network. If you'd like to, run the latest tagged version in production instead.

from the root folder, run make (for all target systems/release)
```
make
```

or restrict to a specific target system
```
# for windows
make windows

# for linux
make linux

# for osx
make osx

# for arm6
make arm6
```

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

### How to register a channel

1. Register your account with `/quote ACC REGISTER <username> * passphrase :<password>`
2. Join the channel with `/join #channel`
3. Register the channel with `/msg ChanServ REGISTER #channel`

After this, your channel will remember the fact that you're the owner, the topic, and any modes set on it!

Make sure to setup [SASL](https://freenode.net/kb/answer/sasl) in your client to automatically login to your account when you next join the server.


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

### Configuration

* Locations where oragono will read/write files can be configured in the `ircd.yaml` file. (**Note:** this applies to multiple options like database location and certificates as well)

For example, to change the logging destination edit `ircd.yaml` and change this line:
```
    filename: ircd.log
```

To this:
```
    filename: /var/log/ircd.log
```

* When using oragono the `--conf` option can be used to change which/where the configuration file is read from.

For example:
```
oragono run --conf /path/to/ircd.yaml
```

# Credits

* Jeremy Latt, creator of Ergonomadic, <https://github.com/jlatt>
* Edmund Huber, maintainer of Ergonomadic, <https://github.com/edmund-huber>
* Niels Freier, added WebSocket support to Ergonomadic, <https://github.com/stumpyfr>
* Daniel Oakley, maintainer of Oragono, <https://github.com/DanielOaks>
* apologies to anyone I forgot.
