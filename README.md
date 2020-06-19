![Oragono logo](docs/logo.png)

Oragono is a modern IRC server written in Go. Its core design principles are:

* Being simple to set up and use
* Combining the features of an ircd, a services framework, and a bouncer (integrated account management, history storage, and bouncer functionality)
* Bleeding-edge [IRCv3 support](https://ircv3.net/software/servers.html), suitable for use as an IRCv3 reference implementation
* Highly customizable via a rehashable (i.e., reloadable at runtime) YAML config

Oragono is a fork of the [Ergonomadic](https://github.com/jlatt/ergonomadic) IRC daemon <3

---

[![Go Report Card](https://goreportcard.com/badge/github.com/oragono/oragono)](https://goreportcard.com/report/github.com/oragono/oragono)
[![Build Status](https://travis-ci.com/oragono/oragono.svg?branch=master)](https://travis-ci.com/oragono/oragono)
[![Download Latest Release](https://img.shields.io/badge/downloads-latest%20release-green.svg)](https://github.com/oragono/oragono/releases/latest)
[![Freenode #oragono](https://img.shields.io/badge/Freenode-%23oragono-1e72ff.svg?style=flat)](https://www.irccloud.com/invite?channel=%23oragono&hostname=irc.freenode.net&port=6697&ssl=1)
[![Crowdin](https://d322cqt584bo4o.cloudfront.net/oragono/localized.svg)](https://crowdin.com/project/oragono)

If you want to take a look at a running Oragono instance or test some client code, feel free to play with [testnet.oragono.io](https://testnet.oragono.io/) (TLS on port 6697 or plaintext on port 6667).

---


## Features

* integrated services: NickServ for user accounts, ChanServ for channel registration, and HostServ for vanity hosts
* bouncer-like features: storing and replaying history, allowing multiple clients to use the same nickname
* UTF-8 nick and channel names with rfc7613 (PRECIS)
* native TLS/SSL support, including support for client certificates
* [yaml](https://yaml.org/) configuration
* updating server config and TLS certificates on-the-fly (rehashing)
* SASL authentication
* LDAP support
* supports [multiple languages](https://crowdin.com/project/oragono) (you can also set a default language for your network)
* advanced security and privacy features (support for requiring SASL for all logins, cloaking IPs, and running as a Tor hidden service)
* an extensible privilege system for IRC operators
* ident lookups for usernames
* automated client connection limits
* passwords stored with [bcrypt](https://godoc.org/golang.org/x/crypto)
* banning ips/nets and masks with `KLINE` and `DLINE`
* [IRCv3 support](https://ircv3.net/software/servers.html)
* a heavy focus on developing with [specifications](https://oragono.io/specs.html)

## Quick start guide

Download the latest release from this page: https://github.com/oragono/oragono/releases/latest

Extract it into a folder, then run the following commands:

```sh
cp default.yaml ircd.yaml
vim ircd.yaml   # modify the config file to your liking
oragono mkcerts
oragono run     # server should be ready to go!
```

**Note:** See the [productionizing guide in our manual](https://github.com/oragono/oragono/blob/master/docs/MANUAL.md#productionizing) for recommendations on how to run a production network, including obtaining valid TLS certificates.

### Platform Packages

Some platforms/distros also have Oragono packages maintained for them:

* Arch Linux [AUR](https://aur.archlinux.org/packages/oragono/) - Maintained by [Sean Enck (@enckse)](https://github.com/enckse).

### Using Docker

A Dockerfile and example docker-compose recipe are available in the `distrib/docker` directory. Oragono is automatically published
to Docker Hub at [oragono/oragono](https://hub.docker.com/r/oragono/oragono). For more information, see the distrib/docker
[README file](https://github.com/oragono/oragono/blob/master/distrib/docker/README.md).

### From Source

You can also install this repo and use that instead! However, keep some things in mind if you go that way:

`devel` branches are intentionally unstable, containing fixes that may not work, and they may be rebased or reworked extensively.

The `master` branch _should_ usually be stable, but may contain database changes that either have not been finalised or not had database upgrade code written yet. Don't run `master` on a live production network.

The `stable` branch contains the latest release. You can run this for a production version without any trouble.

#### Building

You'll need an [up-to-date distribution of the Go language for your OS and architecture](https://golang.org/dl/). Once you have that, just clone the repository and run `make build`. If everything goes well, you should now have an executable named `oragono` in the base directory of the project.

## Configuration

The default config file [`default.yaml`](default.yaml) helps walk you through what each option means and changes.

You can use the `--conf` parameter when launching Oragono to control where it looks for the config file. For instance: `oragono run --conf /path/to/ircd.yaml`. The configuration file also stores where the log, database, certificate, and other files are opened. Normally, all these files use relative paths, but you can change them to be absolute (such as `/var/log/ircd.log`) when running Oragono as a service.

### Logs

By default, logs go to stderr only. They can be configured to go to a file, or you can use systemd to direct the stderr to the system journal (see the manual for details). The configuration format of logs is designed to be easily pluggable, and is inspired by the logging config provided by InspIRCd.

### Passwords

Passwords (for both `PASS` and oper logins) are stored using bcrypt. To generate encrypted strings for use in the config, use the `genpasswd` subcommand as such:

```sh
oragono genpasswd
```

With this, you receive a blob of text which you can plug into your configuration file.

### How to register a channel

1. Register your account with `/NS REGISTER <password>`
2. Join the channel with `/join #channel`
3. Register the channel with `/CS REGISTER #channel`

After this, your channel will remember the fact that you're the owner, the topic, and any modes set on it!

Make sure to setup [SASL](https://freenode.net/kb/answer/sasl) in your client to automatically login to your account when you next join the server.


# Credits

* Jeremy Latt (2012-2014)
* Edmund Huber (2014-2015)
* Daniel Oaks (2016-present)
* Shivaram Lingamneni (2017-present)
* [Many other contributors and friends of the project <3](https://github.com/oragono/oragono/blob/master/CHANGELOG.md)
