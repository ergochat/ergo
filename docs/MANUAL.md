         __ __  ______ ___  ______ ___ 
      __/ // /_/ ____/ __ \/ ____/ __ \
     /_  // __/ __/ / /_/ / / __/ / / /
    /_  // __/ /___/ _, _/ /_/ / /_/ / 
     /_//_/ /_____/_/ |_|\____/\____/  

             Ergo IRCd Manual
            https://ergo.chat/


_Copyright © Daniel Oaks <daniel@danieloaks.net>, Shivaram Lingamneni <slingamn@cs.stanford.edu>_


--------------------------------------------------------------------------------------------


 Table of Contents

- [Introduction](#introduction)
    - [Project Basics](#project-basics)
    - [Scalability](#scalability)
- [Installing](#installing)
    - [Windows](#windows)
    - [macOS / Linux / Raspberry Pi](#macos--linux--raspberry-pi)
    - [Docker](#docker)
    - [Becoming an operator](#becoming-an-operator)
    - [Rehashing](#rehashing)
    - [Environment variables](#environment-variables)
    - [Productionizing with systemd](#productionizing-with-systemd)
    - [Using valid TLS certificates](#using-valid-tls-certificates)
    - [Upgrading to a new version of Ergo](#upgrading-to-a-new-version-of-ergo)
- [Features](#features)
    - [User Accounts](#user-accounts)
    - [Account/Nick Modes](#accountnick-modes)
        - [Nick equals account](#nick-equals-account)
        - [Lenient nick reservation](#lenient-nick-reservation)
        - [No nick reservation](#no-nick-reservation)
        - [SASL-only mode](#sasl-only-mode)
    - [Email verification](#email-verification)
    - [Channel Registration](#channel-registration)
    - [Language](#language)
    - [Multiclient ("Bouncer")](#multiclient-bouncer)
    - [History](#history)
    - [Persistent history with MySQL](#persistent-history-with-mysql)
    - [IP cloaking](#ip-cloaking)
    - [Moderation](#moderation)
    - [Push notifications](#push-notifications)
- [Frequently Asked Questions](#frequently-asked-questions)
- [IRC over TLS](#irc-over-tls)
    - [Redirect from plaintext to TLS](#how-can-i-redirect-users-from-plaintext-to-tls)
    - [Reverse proxies](#reverse-proxies)
    - [Client certificates](#client-certificates)
    - [SNI](#sni)
- [Modes](#modes)
    - [User Modes](#user-modes)
    - [Channel Modes](#channel-modes)
    - [Channel Prefixes](#channel-prefixes)
- [Commands](#commands)
- [Working with other software](#working-with-other-software)
    - [Kiwi IRC and Gamja](#kiwi-irc-and-gamja)
    - [Migrating from Anope or Atheme](#migrating-from-anope-or-atheme)
    - [HOPM](#hopm)
    - [Tor](#tor)
    - [I2P](#i2p)
    - [ZNC](#znc)
    - [API](#api)
    - [External authentication systems](#external-authentication-systems)
    - [DNSBLs and other IP checking systems](#dnsbls-and-other-ip-checking-systems)
- [Acknowledgements](#acknowledgements)

--------------------------------------------------------------------------------------------


# Introduction

This document goes over the Ergo IRC server, how to get it running and how to use it once it is up and running!

If you have any suggestions, issues or questions, feel free to submit an issue on our [GitHub repo](https://github.com/ergochat/ergo) or ask in our channel [`#ergo` on irc.ergo.chat](ircs://irc.ergo.chat:6697/#ergo) or [`#ergo` on irc.libera.chat](ircs://irc.libera.chat:6697/#ergo).


## Project Basics

Ergo is an ircd written "from scratch" in the [Go](https://en.wikipedia.org/wiki/Go_%28programming_language%29) language, i.e., it [shares no code](https://github.com/grawity/irc-docs/blob/master/family-tree.txt) with the original ircd implementation or any other major ircd. It began as [ergonomadic](https://github.com/jlatt/ergonomadic), which was developed by Jeremy Latt between 2012 and 2014. In 2016, Daniel Oaks forked the project under the name Oragono, in order to prototype [IRCv3](https://ircv3.net/) features and for use as a reference implementation of the [Modern IRC specification](https://modern.ircdocs.horse). Oragono 1.0.0 was released in February 2019; the project switched to its current name of Ergo in June 2021.

Ergo's core design goals are:

* Being simple to set up and use
* Combining the features of an ircd, a services framework, and a bouncer (integrated account management, history storage, and bouncer functionality)
* Bleeding-edge [IRCv3 support](http://ircv3.net/software/servers.html), suitable for use as an IRCv3 reference implementation
* High customizability via a rehashable (i.e., reloadable at runtime) YAML config

In addition to its unique features (integrated services and bouncer, comprehensive internationalization), Ergo also strives for feature parity with other major servers. Ergo is a mature project with multiple communities using it as a day-to-day chat server --- we encourage you to consider it for your organization or community!

## Scalability

We believe Ergo should scale comfortably to 10,000 clients and 2,000 clients per channel, making it suitable for small to medium-sized teams and communities. Ergo does not currently support server-to-server linking (federation), meaning that all clients must connect to the same instance. However, since Ergo is implemented in Go, it is reasonably effective at distributing work across multiple cores on a single server; in other words, it should "scale up" rather than "scaling out". (Horizontal scalability is [planned](https://github.com/ergochat/ergo/issues/1532) but is not scheduled for development in the near term.)

Even though it runs as a single instance, Ergo can be deployed for high availability (i.e., with no single point of failure) using Kubernetes. This technique uses a k8s [LoadBalancer](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/) to receive external traffic and a [Volume](https://kubernetes.io/docs/concepts/storage/volumes/) to store the embedded database file. See [Hashbang's implementation](https://github.com/hashbang/gitops/tree/master/ircd) for a "worked example".

If you're interested in deploying Ergo at scale or for high availability, or want performance tuning advice, come find us on [`#ergo` on Libera](ircs://irc.libera.chat:6697/#ergo), we're very interested in what our software can do!


--------------------------------------------------------------------------------------------


# Installing

In this section, we'll explain how to install and use the Ergo IRC server.


## Windows

To get started with Ergo on Windows:

1. Make sure you have the [latest release](https://github.com/ergochat/ergo/releases/latest) downloaded.
1. Extract the zip file to a folder.
1. Copy and rename `default.yaml` to `ircd.yaml`.
1. Open up `ircd.yaml` using any text editor, and then save it once you're happy.
1. Open up a `cmd.exe` window, then `cd` to where you have Ergo extracted.
1. Run `ergo mkcerts` if you want to generate new self-signed SSL/TLS certificates (note that you can't enable STS if you use self-signed certs).

To start the server, type `ergo run` and hit enter, and the server should start!


## macOS / Linux / Raspberry Pi

To get started with Ergo on macOS, Linux, or on a Raspberry Pi:

1. Make sure you have the [latest release](https://github.com/ergochat/ergo/releases/latest) for your OS/distro downloaded.
1. Extract the tar.gz file to a folder.
1. Copy and rename `default.yaml` to `ircd.yaml`.
1. Open up `ircd.yaml` using any text editor, and then save it once you're happy.
1. Open up a Terminal window, then `cd` to where you have Ergo extracted.
1. Run `./ergo mkcerts` if you want to generate new self-signed SSL/TLS certificates (note that you can't enable STS if you use self-signed certs).

To start the server, type `./ergo run` and hit enter, and the server should be ready to use!


## Docker

1. Pull the latest version of Ergo: `docker pull ghcr.io/ergochat/ergo:stable`
1. Create a volume for persistent data: `docker volume create ergo-data`
1. Run the container, exposing the default ports: `docker run -d --name ergo -v ergo-data:/ircd -p 6667:6667 -p 6697:6697 ghcr.io/ergochat/ergo:stable`

For further information and a sample docker-compose file see the separate [Docker documentation](https://github.com/ergochat/ergo/blob/master/distrib/docker/README.md).


## Building from source

You'll need an [up-to-date distribution of the Go language for your OS and architecture](https://golang.org/dl/). Once you have that, just clone the repository and run `make build`. If everything goes well, you should now have an executable named `ergo` in the base directory of the project.


## Becoming an operator

Many administrative actions on an IRC server are performed "in-band" as IRC commands sent from a client. The client in question must be an IRC operator ("oper", "ircop"). The easiest way to become an operator on your new Ergo instance is first to pick a strong, secure password, then "hash" it using the `ergo genpasswd` command (run `ergo genpasswd` from the command line, then enter your password twice), then copy the resulting hash into the `opers` section of your `ircd.yaml` file. Then you can become an operator by issuing the IRC command: `/oper admin mysecretpassword`.

The operator defined in the default configuration file is named `admin` and has full administrative privileges on the server; see the `oper-classes` and `opers` blocks for information on how to define additional operators, or less privileged operators.


## Rehashing

The primary way of configuring Ergo is by modifying the configuration file. Most changes to the configuration file can be applied at runtime by "rehashing", i.e., reloading the configuration file without restarting the server process. This has the advantage of not disconnecting users. There are two ways to rehash Ergo:

1. If you are an operator with the `rehash` capability, you can issue the `/REHASH` command (you may have to `/quote rehash`, depending on your client)
1. You can send the `SIGHUP` signal to Ergo, e.g., via `killall -HUP ergo`

Rehashing also reloads TLS certificates and the MOTD. Some configuration settings cannot be altered by rehash. You can monitor either the response to the `/REHASH` command, or the server logs, to see if your rehash was successful.


## Environment variables

Ergo can also be configured using environment variables, using the following technique:

1. Ensure that `allow-environment-variables` is set to `true` in the YAML config file itself (see `default.yaml` for an example)
1. Find the "path" of the config variable you want to override in the YAML file, e.g., `server.websockets.allowed-origins`
1. Convert each path component from "kebab case" to "screaming snake case", e.g., `SERVER`, `WEBSOCKETS`, and `ALLOWED_ORIGINS`.
1. Prepend `ERGO` to the components, then join them all together using `__` as the separator, e.g., `ERGO__SERVER__WEBSOCKETS__ALLOWED_ORIGINS`.
1. Set the environment variable of this name to a JSON (or YAML) value that will be deserialized into this config field, e.g., `export ERGO__SERVER__WEBSOCKETS__ALLOWED_ORIGINS='["https://irc.example.com", "https://chat.example.com"]'`

However, settings that were overridden using this technique cannot be rehashed --- changing them will require restarting the server.


## Productionizing with systemd

The recommended way to operate ergo as a service on Linux is via systemd. This provides a standard interface for starting, stopping, and rehashing (via `systemctl reload`) the service. It also captures ergo's loglines (sent to stderr in the default configuration) and writes them to the system journal.

The only major distribution that currently packages Ergo is Arch Linux; the aforementioned AUR package includes a systemd unit file. However, it should be fairly straightforward to set up a productionized Ergo on any Linux distribution. Here's a quickstart guide for Debian/Ubuntu:

1. Create a dedicated, unprivileged role user who will own the ergo process and all its associated files: `adduser --system --group --home=/home/ergo ergo`. This user now has a home directory at `/home/ergo`. To prevent other users from viewing Ergo's configuration file, database, and certificates, restrict the permissions on the home directory: `chmod 0700 /home/ergo`.
1. Copy the executable binary `ergo`, the config file `ircd.yaml`, the database `ircd.db`, and the self-signed TLS certificate (`fullchain.pem` and `privkey.pem`) to `/home/ergo`. (If you don't have an `ircd.db`, it will be auto-created as `/home/ergo/ircd.db` on first launch.) Ensure that they are all owned by the new ergo role user: `sudo chown -R ergo:ergo /home/ergo`. Ensure that the configuration file logs to stderr.
1. Install our example [ergo.service](https://github.com/ergochat/ergo/blob/stable/distrib/systemd/ergo.service) file to `/etc/systemd/system/ergo.service`.
1. Enable and start the new service with the following commands:
    1. `systemctl daemon-reload`
    1. `systemctl enable ergo.service`
    1. `systemctl start ergo.service`
    1. Confirm that the service started correctly with `systemctl status ergo.service`


On a non-systemd system, ergo can be configured to log to a file and used [logrotate(8)](https://linux.die.net/man/8/logrotate), since it will reopen its log files (as well as rehashing the config file) upon receiving a SIGHUP. To rehash manually outside the context of log rotation, you can use `killall -HUP ergo` or `pkill -HUP ergo`. See [distrib/init](https://github.com/ergochat/ergo/tree/master/distrib/init) for init scripts and related tools for non-systemd systems.


## Using valid TLS certificates

The other major hurdle for productionizing (but one well worth the effort) is obtaining valid TLS certificates for your domain, if you haven't already done so:

1. The simplest way to get valid TLS certificates is from [Let's Encrypt](https://letsencrypt.org/) with [Certbot](https://certbot.eff.org/). The correct procedure will depend on whether you are already running a web server on port 80. If you are, follow the guides on the Certbot website; if you aren't, you can use `certbot certonly --standalone --preferred-challenges http -d example.com` (replace `example.com` with your domain).
1. At this point, you should have certificates available at `/etc/letsencrypt/live/example.com` (replacing `example.com` with your domain). You should serve `fullchain.pem` as the certificate and `privkey.pem` as its private key. However, these files are owned by root and the private key is not readable by the ergo role user, so you won't be able to use them directly in their current locations. You can write a renewal deploy hook for certbot to make copies of these certificates accessible to the ergo role user. For example, install the following script as `/etc/letsencrypt/renewal-hooks/deploy/install-ergo-certificates` (which will update the certificate and key after a successful renewal), again replacing `example.com` with your domain name, and chmod it 0755:

````bash
#!/bin/bash

set -eu

umask 077
cp /etc/letsencrypt/live/example.com/fullchain.pem /home/ergo/
cp /etc/letsencrypt/live/example.com/privkey.pem /home/ergo/
chown ergo:ergo /home/ergo/*.pem
# rehash ergo, which will reload the certificates:
systemctl reload ergo.service
````

Executing this script manually will install the certificates for the first time and perform a rehash, enabling them.

If you are using Certbot 0.29.0 or higher, you can also change the ownership of the files under `/etc/letsencrypt` so that the ergo user can read them, as described in the [UnrealIRCd documentation](https://www.unrealircd.org/docs/Setting_up_certbot_for_use_with_UnrealIRCd#Tweaking_permissions_on_the_key_file).


## Upgrading to a new version of Ergo

As long as you are using official releases or release candidates of Ergo, any backwards-incompatible changes should be described in the changelog.

In general, the config file format should be fully backwards and forwards compatible. Unless otherwise noted, no config file changes should be necessary when upgrading Ergo. However, the "config changes" section of the changelog will typically describe new sections that can be added to your config to enable new functionality, as well as changes in the recommended values of certain fields.

The database is versioned; upgrades that involve incompatible changes to the database require updating the database. If you have `datastore.autoupgrade` enabled in your config, the database will be backed up and upgraded when you restart your server when required. Otherwise, you can apply upgrades manually:

1. Stop your server
1. Make a backup of your database file
1. Run `ergo upgradedb` (from the same working directory and with the same arguments that you would use when running `ergo run`)
1. Start the server again

If you want to run our master branch as opposed to our releases, come find us in our channel and we can guide you around any potential pitfalls.


--------------------------------------------------------------------------------------------


# Features

In this section, we'll explain and go through using various features of the Ergo IRC server.


## User Accounts

In most IRC servers you can use `NickServ` to register an account. You can do the same thing with Ergo, by default, with no other software needed!

To register an account, use:

    /NS REGISTER <password>

or

    /msg nickserv register <password>

This is the way to go if you want to use a regular password. `<password>` is your password, your current nickname will become your username. Your password cannot contain spaces, but make sure to use a strong one anyway.

If you want to use a TLS client certificate instead of a password to authenticate (`SASL EXTERNAL`), then you can use the command below to do so. (If you're not sure what this is, don't worry – just use the above password method to register an account.)

    /NS REGISTER *

Once you've registered, you'll need to set up SASL to login. One of the more complete SASL instruction pages is libera.chat's page [here](https://libera.chat/guides/sasl). Open up that page, find your IRC client and then setup SASL with your chosen username and password!

If your client doesn't support SASL, you can typically use the "server password" (`PASS`) field in your client to log into your account automatically when connecting. Set the server password to `accountname:accountpassword`, where `accountname` is your account name and `accountpassword` is your account password.

## Account/Nick Modes

Ergo supports several different modes of operation with respect to accounts and nicknames.

### Nick equals account

In this mode (the default), registering an account gives you privileges over the use of the account name as a nickname. The server will then enforce several invariants with regard to your nickname:

1. Only you can use your nickname, i.e., clients cannot use your nickname unless they are logged into your account
1. You must use your nickname, i.e., if you are logged into your account, then the server will require you to use your account name as your nickname
1. If you unregister your account, your nickname will be permanently unreclaimable (thus preventing people from impersonating you)

In this mode, it is very important that end users authenticate to their accounts as part of the initial IRC handshake (traditionally referred to as "connection registration"); otherwise they will not be able to use their registered nicknames. The preferred mechanism for this is [SASL](https://libera.chat/guides/sasl), which is supported by most modern clients. As a fallback, this can also be done via the `PASS` (server password) command; set the "server password" field of the client to `AzureDiamond:hunter2`, where `AzureDiamond` is the account name and `hunter2` is the account password.

As an end user, if you want to change your nickname, you can register a new account and transfer any channel ownerships to it using `/msg ChanServ transfer`.

To enable this mode as the server operator, set the following configs (note that they are already set in `default.yaml`):

* `accounts.registration.enabled = true`
* `accounts.authentication-enabled = true`
* `accounts.nick-reservation.enabled = true`
* `accounts.nick-reservation.method = strict`
* `accounts.nick-reservation.allow-custom-enforcement = false`
* `accounts.nick-reservation.force-nick-equals-account = true`

### Lenient nick reservation

In this mode (implemented in the `traditional.yaml` config file example), nickname reservation is available, but end users must opt into it using `/msg NickServ set enforce strict`. Moreover, you need not use your nickname; even while logged in to your account, you can change nicknames to anything that is not reserved by another user. You can reserve some of your alternate nicknames using `/msg NickServ group`.

To enable this mode as the server operator, set the following configs (they are set in `traditional.yaml`):

* `accounts.registration.enabled = true`
* `accounts.authentication-enabled = true`
* `accounts.nick-reservation.enabled = true`
* `accounts.nick-reservation.method = optional`
* `accounts.nick-reservation.allow-custom-enforcement = true`
* `accounts.nick-reservation.force-nick-equals-account = false`

### No nick reservation

This makes Ergo's services act similar to Quakenet's Q bot. In this mode, users cannot own or reserve nicknames. In other words, there is no connection between account names and nicknames. Anyone can use any nickname (as long as it's not already in use by another running client). However, accounts are still useful: they can be used to register channels (see below), and some IRCv3-capable clients (with the `account-tag` or `extended-join` capabilities) may be able to take advantage of them.

To enable this mode, set the following configs:

* `accounts.registration.enabled = true`
* `accounts.authentication-enabled = true`
* `accounts.nick-reservation.enabled = false`

### SASL-only mode

This mode is comparable to Slack, Mattermost, or similar products intended as internal chat servers for an organization or team. In this mode, clients cannot connect to the server unless they log in with SASL as part of the initial handshake. This allows Ergo to be deployed facing the public Internet, with fine-grained control over who can log in.

In this mode, clients must not be allowed to register their own accounts, so user-initiated account registration must be disabled. Accordingly, an operator must do the initial account creation, using the `SAREGISTER` command of NickServ. (For more details, `/msg NickServ help saregister`.) To bootstrap this process, you can make an initial connection from localhost, which is exempt (by default) from the requirement, or temporarily add your own IP to the exemption list. You can also use a more permissive configuration for bootstrapping, then switch to this one once you have your account. Another possibility is permanently exempting an internal network, e.g., `10.0.0.0/8`, that only trusted people can access.

To enable this mode, use the configs from the "nick equals account" section (i.e., start from `default.yaml`) and make these modifications:

* `accounts.registration.enabled = false`
* `accounts.require-sasl.enabled = true`

## Email verification

By default, account registrations complete immediately and do not require a verification step. However, like other service frameworks, Ergo's NickServ can be configured to require email verification of registrations. The main challenge here is to prevent your emails from being marked as spam, which you can do by configuring [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework), [DKIM](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail), and [DMARC](https://en.wikipedia.org/wiki/DMARC). For example, this configuration (when added to the `accounts.registration` section) enables email verification, with the emails being signed with a DKIM key and sent directly from Ergo:

```yaml
        email-verification:
            enabled: true
            sender: "admin@my.network"
            require-tls: true
            helo-domain: "my.network" # defaults to server name if unset
            dkim:
                domain: "my.network"
                selector: "20200229"
                key-file: "dkim.pem"
```

You must create the corresponding TXT record `20200229._domainkey.my.network` to hold your public key.

You can also use an external SMTP server ("MTA", "relay", or "smarthost") to send the email, in which case DKIM signing can be deferred to that server; see the `mta` section of the example config for details.


## Channel Registration

Once you've registered an account, you can also register channels. If you own a channel, you'l be opped whenever you join it, and the topic/modes will be remembered and re-applied whenever anyone rejoins the channel.

To register a channel, make sure you're joined to it and logged into your account. If both those are true, you can send this command to register your account:

    /CS REGISTER #channelname

For example, `/CS REGISTER #channel` will register the channel `#channel` to my account. If you have a registered channel, you can use `/CS OP #channel` to regain ops in it. Right now, the options for a registered channel are pretty sparse, but we'll add more as we go along.

If your friends have registered accounts, you can automatically grant them operator permissions when they join the channel. For more details, see `/CS HELP AMODE`.


## Language

Ergo supports multiple languages! Specifically, once you connect you're able to get server messages in other languages (messages from other users will still be in their original languages, though).

To see which languages are supported, run this command:

    /QUOTE CAP LS 302

In the resulting text, you should see a token that looks something like this:

    draft/languages=11,en,~ro,~tr-TR,~el,~fr-FR,~pl,~pt-BR,~zh-CN,~en-AU,~es,~no

That's the list of languages we support. For the token above, the supported languages are:

- `en`: English
- `en-AU`: Australian English
- `el`: Greek
- `es`: Spanish
- `fr-FR`: French
- `no`: Norwegian
- `pl`: Polish
- `pt-BR`: Brazilian Portugese
- `ro`: Romanian
- `tr-TR`: Turkish
- `zh-CN`: Chinese

To change to a specific language, you can use the `LANGUAGE` command like this:

    /LANGUAGE ro zh-CN

The above will change the server language to Romanian, with a fallback to Chinese. English will always be the final fallback, if there's a line that is not translated. Substitute any of the other language codes in to select other languages, and run `/LANGUAGE en` to get back to standard English.

Our language and translation functionality is very early, so feel free to let us know if there are any troubles with it! If you know another language and you'd like to contribute, we've got a CrowdIn project here: [https://crowdin.com/project/ergochat](https://crowdin.com/project/ergochat)


## Multiclient ("Bouncer")

Traditionally, every connection to an IRC server is separate must use a different nickname. [Bouncers](https://en.wikipedia.org/wiki/BNC_%28software%29#IRC) are used to work around this, by letting multiple clients connect to a single nickname. With Ergo, if the server is configured to allow it, multiple clients can share a single nickname without needing a bouncer. To use this feature, both connections must authenticate with SASL to the same user account and then use the same nickname during connection registration (while connecting to the server) – once you've logged-in, you can't share another nickname.

To enable this functionality, set `accounts.multiclient.enabled` to `true`. Setting `accounts.multiclient.allowed-by-default` to `true` will allow this for everyone. If `allowed-by-default` is `false` (but `enabled` is still `true`), users can opt in to shared connections using `/msg NickServ SET multiclient true`.

You can see a list of your active sessions and their idle times with `/msg NickServ sessions` (network operators can use `/msg NickServ sessions nickname` to see another user's sessions).

Ergo now supports "always-on clients" that remain present on the server (holding their nickname, subscribed to channels, able to receive DMs, etc.) even when no actual clients are connected. To enable this as a server operator, set `accounts.multiclient.always-on` to either `opt-in`, `opt-out`, or `mandatory`. To enable or disable it as a client (if the server setting is `opt-in` or `opt-out` respectively), use `/msg NickServ set always-on true` (or `false`).


## History

Ergo supports two methods of storing history, an in-memory buffer with a configurable maximum number of messages, and persistent history stored in MySQL (with no fixed limits on message capacity). To enable in-memory history, configure `history.enabled` and associated settings in the `history` section. To enable persistent history, enter your MySQL server information in `datastore.mysql` and then enable persistent history storage in `history.persistent`.

Unfortunately, client support for history playback is still patchy. In descending order of support:

1. The [IRCv3 chathistory specification](https://ircv3.net/specs/extensions/chathistory) offers the most fine-grained control over history replay. It is supported by [Gamja](https://git.sr.ht/~emersion/gamja), [Goguma](https://sr.ht/~emersion/goguma/), and [Kiwi IRC](https://github.com/kiwiirc/kiwiirc), and hopefully other clients soon.
1. We emulate the [ZNC playback module](https://wiki.znc.in/Playback) for clients that support it. You may need to enable support for it explicitly in your client (see the "ZNC" section below).
1. If you set your client to always-on (see the previous section for details), you can set a "device ID" for each device you use. Ergo will then remember the last time your device was present on the server, and each time you sign on, it will attempt to replay exactly those messages you missed. There are a few ways to set your device ID when connecting:
    - You can add it to your SASL username with an `@`, e.g., if your SASL username is `alice` you can send `alice@phone`
    - You can add it in a similar way to your IRC protocol username ("ident"), e.g., `alice@phone`
    - If login to user accounts via the `PASS` command is enabled on the server, you can provide it there, e.g., by sending `alice@phone:hunter2` as the server password
1. If you only have one device, you can set your client to be always-on and furthermore `/msg NickServ set autoreplay-missed true`. This will replay missed messages, with the caveat that you must be connecting with at most one client at a time.
1. You can manually request history using `/history #channel 1h` (the parameter is either a message count or a time duration). (Depending on your client, you may need to use `/QUOTE history` instead.)
1. You can autoreplay a fixed number of lines (e.g., 25) each time you join a channel using `/msg NickServ set autoreplay-lines 25`.


## Persistent history with MySQL

On most Linux and POSIX systems, it's straightforward to set up MySQL (or MariaDB) as a backend for persistent history. This increases the amount of history that can be stored, and ensures that message data will be retained on server restart (you can still use the configuration options to set a time limit for retention). Here's a quick start guide for Ubuntu based on [Digital Ocean's documentation](https://www.digitalocean.com/community/tutorials/how-to-install-mysql-on-ubuntu-20-04):

1. Install the `mysql-server` package
1. Run `mysql_secure_installation` as root; this corrects some insecure package defaults
1. Connect to your new MySQL server as root with `mysql --user root`
1. In the MySQL prompt, create a new `ergo` user (substitute a strong password of your own for `hunter2`): `CREATE USER 'ergo'@'localhost' IDENTIFIED BY 'hunter2';`
1. Create the database that history will be stored in: `CREATE DATABASE ergo_history;`
1. Grant privileges on the database to the new user: `GRANT ALL PRIVILEGES ON ergo_history.* to 'ergo'@'localhost';`
1. Enable persistent history in your Ergo config file. At a minimum, you must set `history.persistent.enabled = true`. You may want to modify the other options under `history.persistent` and `history`.
1. Configure Ergo to talk to MySQL (again, substitute the strong password you chose previously for `hunter2`):

```yaml
    mysql:
        enabled: true
        socket-path: "/var/run/mysqld/mysqld.sock"
        user: "ergo"
        password: "hunter2"
        history-database: "ergo_history"
        timeout: 3s
```


## IP cloaking

Unlike many other chat and web platforms, IRC traditionally exposes the user's IP and hostname information to other users. This is in part because channel owners and operators (who have privileges over a single channel, but not over the server as a whole) need to be able to ban spammers and abusers from their channels, including via hostnames in cases where the abuser tries to evade the ban.

IP cloaking is a way of balancing these concerns about abuse with concerns about user privacy. With cloaking, the user's IP address is deterministically "scrambled", typically via a cryptographic [MAC](https://en.wikipedia.org/wiki/Message_authentication_code), to form a "cloaked" hostname that replaces the usual reverse-DNS-based hostname. Users cannot reverse the scrambling to learn each other's IPs, but can ban a scrambled address the same way they would ban a regular hostname.

Ergo supports cloaking, which is enabled by default (via the `server.ip-cloaking` section of the config). However, Ergo's cloaking behavior differs from other IRC software. Rather than scrambling each of the 4 bytes of the IPv4 address (or each 2-byte pair of the 8 such pairs of the IPv6 address) separately, the server administrator configures a CIDR length (essentially, a fixed number of most-significant-bits of the address). The CIDR (i.e., only the most significant portion of the address) is then scrambled atomically to produce the cloaked hostname. This errs on the side of user privacy, since knowing the cloaked hostname for one CIDR tells you nothing about the cloaked hostnames of other CIDRs --- the scheme reveals only whether two users are coming from the same CIDR. We suggest using 32-bit CIDRs for IPv4 (i.e., the whole address) and 64-bit CIDRs for IPv6, since these are the typical assignments made by ISPs to individual customers.

Setting `server.ip-cloaking.num-bits` to 0 gives users cloaks that don't depend on their IP address information at all, which is an option for deployments where privacy is a more pressing concern than abuse. Holders of registered accounts can also use the vhost system (for details, `/msg HostServ HELP`.)


## Moderation

Ergo shares some server operator moderation tools with other ircds. In particular:

1. `/SAMODE` can be used to grant or remove channel privileges. For example, to create an operator in a channel that has no operators: `/SAMODE #channel +o nickname`
2. `/SAJOIN` lets operators join channels despite restrictions, or forcibly join another user to a channel. For example, `/SAJOIN #channel` or `/SAJOIN nickname #channel`.

However, Ergo's multiclient and always-on features mean that abuse prevention (at the server operator level) requires different techniques than a traditional IRC network. Server operators have two principal tools for abuse prevention:

1. `/UBAN`, which can disable user accounts and/or ban offending IPs and networks
2. `/DEFCON`, which can impose emergency restrictions on user activity in response to attacks

See the `/HELP` (or `/HELPOP`) entries for these commands for more information, but here's a rough workflow for mitigating spam or other attacks:

1. Given abusive traffic from a nickname, use `/UBAN INFO <nickname>` to find out information about their connection
2. If they are using an account, suspend the account with `/UBAN ADD <account>`, which will disconnect them
3. If they are not using an account, or if they're spamming new registrations from an IP, you can add a temporary ban on their IP/network with `/UBAN ADD <ip | network>`
4. Subscribe to the `a` snomask to monitor for abusive registration attempts (`/mode mynick +s u`)
5. When facing a flood of abusive registrations that cannot be stemmed with `/DLINE`, use `/DEFCON 4` to temporarily restrict registrations. (At `/DEFCON 2`, all new connections to the server will require SASL, but this will likely be disruptive to legitimate users as well.)

These techniques require operator privileges: `UBAN` requires the `ban` operator capability, subscribing to snomasks requires `snomasks`, and `DEFCON` requires `defcon`. All three of these capabilities are included by default in the `server-admin` role.

For channel operators, `/msg ChanServ HOWTOBAN #channel nickname` will provide similar information about the best way to ban a user from a channel.


## Push notifications

Ergo now has experimental support for push notifications via the [draft/webpush](https://github.com/ircv3/ircv3-specifications/pull/471) IRCv3 specification. Support for push notifications is disabled by default; operators can enable it by setting `webpush.enabled` to `true` in the configuration file. This has security, privacy, and performance implications:

* If push notifications are enabled, Ergo will send HTTP POST requests to HTTP endpoints of the user's choosing. Although the user has limited control over the POST body (since it is encrypted with random key material), and Ergo disallows requests to local or internal IP addresses, this may potentially impact the IP reputation of the Ergo host, or allow an attacker to probe endpoints that whitelist the Ergo host's IP address.
* Push notifications result in the disclosure of metadata (that the user received a message, and the approximate time of the message) to third-party messaging infrastructure. In the typical case, this will include a push endpoint controlled by the application vendor, plus the push infrastructure controlled by Apple or Google.
* The message contents (including the sender's identity) are protected by [encryption](https://datatracker.ietf.org/doc/html/rfc8291) between the server and the user's endpoint device. However, the encryption algorithm is not forward-secret (a long-term private key is stored on the user's device) or post-quantum (the server retains a copy of the corresponding elliptic curve public key).
* Push notifications are relatively expensive to process, and may increase the impact of spam or denial-of-service attacks on the Ergo server.
* Push notifications negate the anonymization provided by Tor and I2P; an Ergo instance intended to run as a Tor onion service ("hidden service") or exclusively behind an I2P address must disable them in the Ergo configuration file.

Operators and end users are invited to share feedback about push notifications, either via the project issue tracker or the support channel. Note that in order to receive push notifications, the user must be logged in with always-on enabled, and must be using a client (e.g. Goguma) that supports them.


-------------------------------------------------------------------------------------------


# Frequently Asked Questions


## How do I submit a suggestion?

Awesome! We love getting new suggestions for features, ways to improve the server and the tooling around it, everything.

There are two ways to make suggestions, either:

- Submit an issue on our [bug tracker](https://github.com/ergochat/ergo/issues).
- Talk to us in the `#ergo` channel on irc.ergo.chat or irc.libera.chat.


## Why can't I connect?

If your client or bot is failing to connect to Ergo, here are some things to check:

1. If your server has a firewall, does it allow traffic to the relevant IRC port? Try `nc -v yourdomain.name 6697` from the client machine to test connectivity to the server's default TLS port.
1. Is your client trying to connect in plaintext to Ergo's TLS port, or vice versa? If your client is configured to use TLS, ensure that it is also configured to connect to Ergo's TLS port (6697 by default). If your client is configured to use plaintext, ensure that it is also configured to connect to the plaintext port (by default, 6667 and only via a loopback IP address such as `127.0.0.1`).
1. Look for error messages on the client side (you may need to enable your client's "raw log").
1. If all else fails, try turning on debug logging on the server side. Find the `logging` section of your Ergo config and change the default `level: info` to `level: debug`. Then rehash or restart Ergo.


## Why can't I oper?

If your `OPER` command fails, check your server logs for more information. Here are some general issues to double-check:

1. Did you correctly generate the hashed password with `ergo genpasswd`?
1. Did you add the password hash to the correct config file, then save the file?
1. Did you rehash or restart Ergo after saving the file?

The config file accepts hashed passwords, not plaintext passwords. You must run `ergo genpasswd`, type your actual password in, and then receive a hashed blob back (it will look like `$2a$04$GvCFlShLZQjId3dARzwOWu9Nvq6lndXINw2Sdm6mUcwxhtx1U/hIm`). Enter that into the relevant `opers` block in your config file, then save the file.

Although it's theoretically possible to use an operator password that contains spaces, your client may not support it correctly, so it's advisable to choose a password without spaces. (The period character `.` is an acceptable alternative separator if your password is based on randomly chosen words.)

After that, you must rehash or restart Ergo to apply the config change. If a rehash didn't accomplish the desired effects, you might want to try a restart instead.


## Why is Ergo ignoring my ident response / USER command?

The default/recommended configuration of Ergo does not query remote ident servers, and furthermore ignores any user/ident sent with the `USER` command. All user/ident fields are set to a constant `~u`. There are a few reasons for this:

1. Remote ident lookups slow down connection initiation and pose privacy and security concerns (since they transmit usernames over the Internet in plaintext).
2. Ident is commonly used to distinguish users connecting from the same trusted shell host or shared bouncer. This is less important with Ergo, which can act as a bouncer itself.
3. Ignoring user/ident simplifies bans; in general, a channel ban in Ergo should target either the nickname or the hostname. As a channel operator, `/msg ChanServ HOWTOBAN #channel nick` will recommend a way of banning any given user.
4. Elaborating on this rationale somewhat: of the various pieces of information we could try to convey in the user/ident field (traditional user/ident, account name, nickname, or host/IP information), any choice would involve either ambiguity (since, e.g. account names can be present or absent) or would be redundant with information we already expose in the nickname or hostname. Coercing the field to `~u` is deterministic, unambiguous, and compatible with typical client behavior (clients should assume that any tilde-prefixed value is untrusted data and can collide arbitrarily with other values from the same hostname).
5. Because of limitations of the IRC protocol, every character of the user/ident field counts against the maximum size of a message that can be sent.

As an operator, you can modify this behavior if desired; see the `check-ident` and `coerce-ident` settings in the config file.


## Why can't I change nicknames?

The default/recommended configuration of Ergo does not allow authenticated users to change their nicknames; an authenticated user must use their account name as their nickname. There are a few reasons for this:

1. Assigning a consistent nickname prevents certain "split-brain" scenarios that break Ergo's "multiclient" functionality. In brief, if two clients are connecting to the same account/identity, but only one of them issues a `/NICK` command, and then one of them subsequently loses and regains its connection to the server, they "break apart": they will have separate identities and channel memberships on the network, and it's difficult to bring them back together again.
2. The use of a consistent nickname reduces the possibility of edge cases in history playback.
3. The use of a consistent nickname simplifies offline messaging (which is a first-class concept for always-on clients).
4. Ergo eliminates the cases in conventional IRC servers that necessitate nickname changes. In particular, you can always claim your nickname, even if the server is still waiting for an old client to time out, and you can connect arbitrarily many clients to the same nickname.

As an operator, you can disable this behavior using the `force-nick-equals-account` setting, but this is discouraged because it has no effect on always-on clients; always-on clients must use their account names as their nicknames regardless of this setting.


## How do I make a private channel?

We recommend that server administrators set the following recommended defaults:

1. `nick-reservation-method: strict`
1. `force-nick-equals-account: true`

These settings imply that any registered account name can be treated as synonymous with a nickname; anyone using the nickname is necessarily logged into the account, and anyone logged into the account is necessarily using the nickname.

Under these circumstances, users can follow the following steps:

1. Register a channel (`/msg ChanServ register #example`)
1. Set it to be invite-only (`/mode #example +i`)
1. Add the desired nick/account names to the invite exception list (`/mode #example +I alice`)
1. Anyone with persistent voice or higher prefix will also be able to join without an invite (`/msg ChanServ amode #example +v alice`)

Similarly, for a public channel (one without `+i`), users can ban nick/account names with `/mode #example +b bob`. (To restrict the channel to users with valid accounts, set it to registered-only with `/mode #example +R`.)

## What special privileges do AMODEs contain?

Some persistent modes contain persistent privileges over temporary modes. These are cumulative, meaning that +o will get privileges of +h which again gets privileges of +v.

* AMODE +v will be able to join when the channel is `invite-only` (without being on the +I list).
* AMODE +h will be able to join even if a ban matches them (without being on the +e list).

## How do I send an announcement to all connected users?

Ergo supports a simplified form of the "global notice" or "wallops" capabilities found in other ircds. With the `massmessage` operator capability, you can `/NOTICE $$* text of your announcement`, and it will be sent to all connected users. If you have human-readable hostnames enabled (in the default/recommended configuration they are not), you can also `/NOTICE $#wild*card.host.name`.

## Why does Ergo say my connection is insecure when I'm connected using TLS?

If the client you are connecting with uses the [WebIRC](https://ircv3.net/specs/extensions/webirc.html) command then it is responsible for saying whether the connection is "secure" or not, even if the connection to ergo is made over TLS. For example, a web-based client would mark connections as secure if you used HTTPS but not if you used plain HTTP. Older versions of the WebIRC specification didn't include the secure parameter at all; any connections from software using the older protocol will therefore be treated as insecure by Ergo. 

If you are using a reverse proxy (such as stunnel, nginx, Traefik, or Caddy) to terminate TLS, but the connection between the reverse proxy and Ergo is using a non-loopback IP (i.e. outside the `127.0.0.0/8` or `0::1/128` ranges), then Ergo will view the connection as being "insecure". If the network is in fact secure against passive monitoring and active manipulation (e.g. a trusted LAN, a VPN link, or a Docker internal IP), you can add it to `server.secure-nets`, which will cause the connection to be treated as "secure".

-------------------------------------------------------------------------------------------


# IRC over TLS

IRC has traditionally been available over both plaintext (on port 6667) and SSL/TLS (on port 6697). We recommend that you make your server available exclusively via TLS, since exposing plaintext access allows for unauthorized interception or modification of user data or passwords. The default config file no longer exposes a plaintext port, so if you haven't modified your `listeners` section, you're good to go.

For a quickstart guide to obtaining valid TLS certificates from Let's Encrypt, see the "productionizing" section of the manual above.

## How can I "redirect" users from plaintext to TLS?

The [STS specification](https://ircv3.net/specs/extensions/sts) can be used to redirect clients from plaintext to TLS automatically. If you set `server.sts.enabled` to `true`, clients with specific support for STS that connect in plaintext will disconnect and reconnect over TLS. To use STS, you must be using certificates issued by a generally recognized certificate authority, such as Let's Encrypt.

Many clients do not have this support. However, you can designate port 6667 as an "STS-only" listener: any client that connects to such a listener will receive both the machine-readable STS policy and a human-readable message instructing them to reconnect over TLS, and will then be disconnected by the server before they can send or receive any chat data. Here is an example of how to configure this behavior:

```yaml
    listeners:
        ":6667":
            sts-only: true

        # These are loopback-only plaintext listeners on port 6668:
        "127.0.0.1:6668": # (loopback ipv4, localhost-only)
        "[::1]:6668":     # (loopback ipv6, localhost-only)

        ":6697":
            tls:
                cert: fullchain.pem
                key: privkey.pem

    sts:
        enabled: true

        # how long clients should be forced to use TLS for.
        duration: 1mo2d5m
```

## Reverse proxies

Ergo supports the use of reverse proxies (such as nginx, or a Kubernetes [LoadBalancer](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer)) that sit between it and the client. In these deployments, the [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) is used to pass the end user's IP through to Ergo. These proxies can be used to terminate TLS externally to Ergo, e.g., if you need to support versions of the TLS protocol that are not implemented natively by Go, or if you want to consolidate your certificate management into a single nginx instance.

### IRC Sockets

The first step is to add the reverse proxy's IP to `proxy-allowed-from` and `ip-limits.exempted`. (Use `localhost` to exempt all loopback IPs and Unix domain sockets.)

After that, there are two possibilities:

* If you're using a proxy like nginx or stunnel that terminates TLS, then forwards a PROXY v1 (ASCII) header ahead of a plaintext connection, no further Ergo configuration is required. You need only configure your proxy to send the PROXY header. Here's an [example nginx config](https://github.com/ergochat/testnet.ergo.chat/blob/master/nginx_stream.conf).
* If you're using a cloud load balancer that either sends a PROXY v1 header ahead of unterminated TLS (like [DigitalOcean](https://www.digitalocean.com/docs/networking/load-balancers/#proxy-protocol)) or sends a PROXY v2 (binary) header (like the [AWS "Network Load Balancer"](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html#proxy-protocol)), Ergo must be configured to expect a PROXY header ahead of the connection. Add `proxy: true` to the listener config block, e.g.,

```yaml
        ":6697":
            tls:
                cert: fullchain.pem
                key: privkey.pem
            proxy: true
```

### Websockets through HTTP reverse proxies

Ergo will honor the `X-Forwarded-For` headers on incoming websocket connections, if the peer IP address appears in `proxy-allowed-from`. For these connections, set `proxy: false`, or omit the `proxy` option.


## Client certificates

Ergo supports authenticating to user accounts via TLS client certificates. The end user must enable the client certificate in their client and also enable SASL with the `EXTERNAL` method. To register an account using only a client certificate for authentication, connect with the client certificate and use `/NS REGISTER *` (or `/NS REGISTER * email@example.com` if email verification is enabled on the server). To add a client certificate to an existing account, obtain the SHA-256 fingerprint of the certificate (either by connecting with it and looking at your own `/WHOIS` response, in particular the `276 RPL_WHOISCERTFP` line, or using the openssl command `openssl x509 -noout -fingerprint -sha256 -in example_client_cert.pem`), then use the `/NS CERT` command).

Client certificates are not supported over websockets due to a [Chrome bug](https://bugs.chromium.org/p/chromium/issues/detail?id=329884).

## SNI

Ergo supports [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication); this is useful if you have multiple domain names for your server, with different certificates covering different domain names. Configure your TLS listener like this:

```yaml
        ":6697":
            tls-certificates:
                -
                    cert: cert1.pem
                    key:  key1.pem
                -
                    cert: cert2.pem
                    key:  key2.pem
```

If multiple certificates are applicable, or the client does not send SNI, the server will offer the first applicable certificate in the list.

--------------------------------------------------------------------------------------------


# Modes

On IRC, you can set modes on users and on channels. Modes are basically extra information that changes how users and channels work.

In this section, we give an overview of the modes Ergo supports.


## User Modes

These are the modes which can be set on you when you're connected.

### +i - Invisible

If this mode is set, you're marked as 'invisible'. This means that your channels won't be shown when users `/WHOIS` you (except for IRC operators, they can see all the channels you're in).

To set this mode on yourself:

    /mode dan +i

### +o - Operator

If this mode is set, you're marked as an 'IRC Operator'. This means that you're an admin of some sort on the server and have some special powers regular users don't have. To set this mode, you authenticate (oper-up) using the `/OPER` command.

### +R - Registered-Only

If this mode is set, you'll only receive messages from other users if they're logged into an account. If a user who isn't logged-in messages you, you won't see their message.

To set this mode on yourself:

    /mode dan +R

To unset this mode and let anyone speak to you:

    /mode dan -R

### +s - Server Notice Masks ("snomasks")

This is a special 'list mode'. If you're an IRC operator, this mode lets you see special server notices that get sent out. See `/helpop snomasks` (as an operator) for more information on this mode.

### +Z - TLS

This mode is automatically set if you're connecting using SSL/TLS. There's no way to set this yourself, and it's automatically set or not set when you connect to the server.

### +B - Bot

If this mode is set, you are marked as a 'Bot'. The bot can set this mode on itself. This adds additional information in response to WHOIS

    /WHOIS Bot

will return an extra response of `RPL_WHOISBOT` with the numeric `335` which can be used to identify said Bot.

### +T - No CTCPs

If this mode is set, you will not recieve CTCP messages.

To set this mode on yourself:

    /mode dan +T

To unset this mode and recieve CTCP messages:

    /mode dan -T

## Channel Modes

These are the modes that can be set on channels when you're a channel operator!

### +b - Ban

With this channel mode, you can change and see who's banned from the channel. Specifically, you can ban 'masks', or a set of nickname, username and hostname.

Here's an example of banning a user named **bob** from channel #test:

    /MODE #test +b bob!*@*

Let's say that **bob** is connecting from the address `192.168.0.234`. You could also do this to ban him:

    /MODE #test +b *!*@192.168.0.234

Banning **bob** in this way means that nobody from that address can connect.

To remove a ban, you do the same thing with `-b` instead of `+b`.

To view the bans that exist on the channel, you can do this instead:

    /MODE #test b

#### Extended Bans

Users can be muted rather than banned by prefixing a ban mask with `m:`. This prevents matching users from speaking in the channel, without kicking them or preventing them from joining the channel. For example, to mute a user named **bob** in the channel #test:

    /MODE #test +b m:bob!*@*

The mute can be removed with `-b` instead of `+b`.

### +e - Ban-Exempt

With this channel mode, you can change who's allowed to bypass bans. For example, let's say you set these modes on the channel:

    /MODE #test +b *!*@192.168.0.234
    /MODE #test +e bob!*@*

This means that **bob** will always be able to join, even if he's connecting from `192.168.0.234`.

For everything else, this mode acts like the `+b - Ban` mode.

### +f - Forward

This channel mode takes another channel as its parameter. Users who are unable to join this channel are forwarded to the provided channel instead.

You need be a channel operator in both channels in order to set this mode.

    /MODE #test +f #foo

This means that users who attempt to join `#test`, but cannot due to another channel mode like `+i` or `+l`, will be forwarded to `#foo` instead.

### +i - Invite-Only

If this channel mode is set on a channel, users will only be able to join if a channel operator has `/INVITE`'d them first.

To set a channel to invite-only:

    /MODE #test +i

To unset the mode and let anyone join (and invite):

    /MODE #test -i

### +I - Invite-Exempt

With this channel mode, you can change who's allowed to join the channel when the `+i - Invite-Only` mode is enabled.

For example, let's say you set these modes on the channel:

    /MODE #test +i
    /MODE #test +I bob!*@*

This means that **bob** will be able to join even without being `/INVITE`'d.

For everything else, this mode acts like the `+b - Ban` mode.

### +k - Key

This channel mode lets you set a 'key' that other people will need to join your channel. To set a key:

    /MODE #test +k p4ssw0rd

Then, to join users will need to do `/JOIN #test p4ssw0rd`. If they try to join without the key, they will be rejected.

To unset the key:

    /MODE #test -k

### +l - Limit

This mode lets you restrict how many users can join the channel.

Let's say that `#test` currently has 5 users in it, and you run this command:

    /MODE #test +l 6

Only one more user will be able to join the channel. If anyone tries to join the channel when there's already six people on it, they will get rejected.

Just like the `+k - Key` mode, to unset the limit:

    /MODE #test -l

### +m - Moderated

This mode lets you restrict who can speak in the channel. If the `+m` mode is enabled, normal users won't be able to say anything. Users who are Voice, Halfop, Channel-Op, Admin and Founder will be able to talk.

To set this mode:

    /MODE #test +m

To unset this mode (and let everyone speak again):

    /MODE #test -m

### +n - No Outside Messages

This mode is enabled by default, and means that only users who are joined to the channel can send messages to it.

If this mode is unset, users who aren't on your channel can send messages to it. This can be useful with, for example, GitHub or notification bots if you want them to send messages to your channel but don't want them to clutter your channel with by joining and leaving it.

### +R - Only Registered Users Can Join

If this mode is set, only users that have logged into an account will be able to join the channel. If this is set and a regular, un-logged-in user tries to join, they will be rejected.

Unregistered users already joined to the channel will not be kicked automatically. They will still be able to speak, unless they are restricted from doing so by another channel mode like +M.  If they leave, they will not be allowed to rejoin.

To set this mode:

    /MODE #test +R

To unset this mode:

    /MODE #test -R

### +M - Only Registered Users Can Speak

If this mode is set, only users that have logged into an account will be able to speak on the channel. Unregistered users may still join the channel, unless they are restricted from doing so by another channel mode like +R. When an unregistered user tries to speak, they will be rejected. Users who have been voiced (+v) are excepted from this restriction.

To set this mode:

    /MODE #test +M

To unset this mode:

    /MODE #test -M

### +s - Secret

If this mode is set, it means that your channel should be marked as 'secret'. Your channel won't show up in `/LIST` or `/WHOIS`, and non-members won't be able to see its members with `/NAMES` or `/WHO`.

To set this mode:

    /MODE #test +s

To unset this mode:

    /MODE #test -s

### +t - Op-Only Topic

This mode is enabled by default, and means that only channel operators can change the channel topic (using the `/TOPIC` command).

If this mode is unset, anyone will be able to change the channel topic.

### +C - No CTCPs

This mode means that [client-to-client protocol](https://tools.ietf.org/id/draft-oakley-irc-ctcp-02.html) messages other than `ACTION` (`/me`) cannot be sent to the channel.

### +u - Auditorium

This mode means that `JOIN`, `PART`, and `QUIT` lines for unprivileged users (i.e., users without a channel prefix like `+v` or `+o`) re not sent to other unprivileged users. In conjunction with `+m`, this is suitable for "public announcements" channels.

### +U - Op-Moderated

This mode means that messages from unprivileged users are only sent to channel operators (who can then decide whether to grant the user `+v`).

## Channel Prefixes

Users on a channel can have different permission levels, which are represented by having different characters in front of their nickname. This section explains the prefixes and what each one means.

### +q (~) - Founder

This prefix means that the given user is the founder of the channel. For example, if `~dan` is on a channel it means that **dan** founded the channel. The 'founder' prefix only appears on channels that are registered.

Founders have complete administrative control of the channel. They can take any action and modify anyone else's privileges.

### +a (&) - Admin

This prefix means that the given user is an admin on the channel. For example, if `&tom` is on a channel, then **tom** is an admin on it. The 'admin' prefix only appears on channels that are registered.

Admins have the same moderation privileges as channel operators (see below), but they can't be kicked or demoted by other admins or channel operators.

### +o (@) - Channel Operator

This prefix means that the given user is an operator on the channel (chanop, for short). For example, if `@ruby` is on a channel, then **ruby** is an op.

Chanops are the default type of channel moderators. They can change the channel modes, ban/kick users, and add or remove chanop (or lower) privileges from users. They can also invite users to invite-only channels.

### +h (%) - Halfop

This prefix means that the given user is a halfop on the channel (half-operator). For example, if `%twi` is on a channel, then **twi** is a halfop.

Halfops have some moderation privileges: they can kick users (but not ban them), change the channel topic, and grant voice privileges (see below).

### +v (+) - Voice

This prefix means that the given user is 'voiced' on the channel. For example, if `+faust` is on a channel, then **faust** is voiced on that channel.

Voiced users can speak when the channel has `+m` (moderated) mode enabled. They get no other special privileges or any moderation abilities.


--------------------------------------------------------------------------------------------


# Commands

The best place to look for command help is on a running copy or Ergo itself!

To see the integrated command help, simply spin up a copy of Ergo and then run this command:

    /HELPOP <command>

If that doesn't work, you may need to run this instead:

    /QUOTE HELP <command>

We may add some additional notes here for specific commands down the line, but right now the in-server docs are the best ones to consult.


--------------------------------------------------------------------------------------------


# Working with other software

Ergo should interoperate with most IRC-based software, including bots. If you have problems getting your preferred software to work with Ergo, feel free to report it to us. If the root cause is a bug in Ergo, we'll fix it.

One exception is services frameworks like [Anope](https://github.com/anope/anope) or [Atheme](https://github.com/atheme/atheme); we have our own services implementations built directly into the server, and since we don't support federation, there's no place to plug in an alternative implementation. (If you are already using Anope or Atheme, we support migrating your database --- see below.)

If you're looking for a bot that supports modern IRCv3 features, check out [bitbot](https://github.com/jesopo/bitbot/)!

## Kiwi IRC and Gamja

We recommend two web-based clients for use with Ergo: [Kiwi IRC](https://github.com/kiwiirc/kiwiirc/) and [Gamja](https://git.sr.ht/~emersion/gamja). Both clients are 100% static files (HTML and Javascript), running entirely in the end user's browser without the need for a separate server-side backend. They can connect directly to Ergo, using Ergo's support for native websockets. Both clients support Ergo's server-side history features; for a demonstration, see the Ergo testnet (click [here for Kiwi](https://testnet.ergo.chat/kiwi/) or [here for Gamja](https://testnet.ergo.chat/gamja)).

For best interoperability with firewalls, you should run an externally facing web server on port 443 that can serve both the static files and the websocket path, then have it reverse-proxy the websocket path to Ergo. For example, configure the following listener in ircd.yaml:

```yaml
        "127.0.0.1:8067":
            websocket: true
```

then the following location block in your nginx config (this proxies only `/webirc` on your server to Ergo's websocket listener):

```
	location /webirc {
		proxy_pass http://127.0.0.1:8067;
		proxy_read_timeout 600s;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection "Upgrade";
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
	}
```

then add the following `startupOptions` to Kiwi's `static/config.json` file (see the [Ergo testnet's config.json](https://testnet.ergo.chat/kiwi/static/config.json) for a fully functional example):

```
    "startupOptions" : {
        "websocket": "wss://domain.example.com/webirc",
        "channel": "#chat",
        "nick": "kiwi-n?"
    },
```

or with Gamja, create a new `config.json` (in the base directory of the Gamja install, alongside Gamja's `index.html`) file along these lines:

```
{
        "server": {
                "url": "wss://domain.example.com/webirc",
                "autojoin": "#chat",
                "auth": "optional"
        }
}
```

On Apache 2.4.47 or higher, websocket proxying can be configured with:

```
RequestHeader setifempty X-Forwarded-Proto https

ProxyPreserveHost On
ProxyPass /webirc http://127.0.0.1:8067 upgrade=websocket
ProxyPassReverse /webirc http://127.0.0.1:8067
```

On Caddy, websocket proxying can be configured with:

```
handle_path /webirc {
  reverse_proxy 127.0.0.1:8067
}
```

## Migrating from Anope or Atheme

You can import user and channel registrations from an Anope or Atheme database into a new Ergo database (not all features are supported). Use the following steps:

1. Obtain the relevant migration tool from the latest stable release: [anope2json.py](https://github.com/ergochat/ergo/blob/stable/distrib/anope/anope2json.py) or [atheme2json.py](https://github.com/ergochat/ergo/blob/stable/distrib/atheme/atheme2json.py) respectively.
1. Make a copy of your Anope or Atheme database file. (You may have to stop and start the services daemon to get it to commit all its changes.)
1. Convert the database to JSON, e.g., with `python3 ./anope2json.py anope.db output.json`
1. Copy your desired Ergo config to `./ircd.yaml` (make any desired edits)
1. Run `ergo importdb ./output.json`
1. Run `ergo mkcerts` if necessary to generate self-signed TLS certificates
1. Run `ergo run` to bring up your new Ergo instance

## Hybrid Open Proxy Monitor (HOPM)

[hopm](https://github.com/ircd-hybrid/hopm) can be used to monitor your server for connections from open proxies, then automatically ban them. To configure hopm to work with Ergo, configure `server.initial_notice` and add operator blocks like this to your Ergo config file, which grant hopm the necessary privileges:

````yaml
server:
    initial-notice: "Welcome to the Ergo IRC server"

# operator classes
oper-classes:
    # hopm
    "hopm":
        # title shown in WHOIS
        title: Proxy Monitor

        # capability names
        capabilities:
        - "kill"
        - "ban"
        - "nofakelag"

# ircd operators
opers:
    # operator named 'hopm'
    hopm:
        # which capabilities this oper has access to
        class: "hopm"

        # custom hostname
        vhost: "proxymonitor.hopm"

        # modes are the modes to auto-set upon opering-up
        modes: +is c

        # password to login with /OPER command
        # generated using  "ergo genpasswd"
        password: "$2a$04$JmsYDY6kX3/wwyK3ao0L7.aGJEto0Xm4DyL6/6zOmCpzeweIb8kdO"
````

Then configure hopm like this:

````
/* replace with the exact notice your server sends on first connection */
target_string = ":ergo.test NOTICE * :*** Welcome to the Ergo IRC server"

/* ergo */
connregex = ".+-.+CONNECT.+-.+ Client Connected \\[([^ ]+)\\] \\[u:([^ ]+)\\] \\[h:([^ ]+)\\] \\[ip:([^ ]+)\\] .+";

/* A DLINE example for ergo */
kline = "DLINE ANDKILL 2h %i :Open proxy found on your host.";
````

## Tor

Ergo has code support for adding an .onion address to an IRC server, or operating an IRC server as a Tor onion service ("hidden service"). This is subtle, so you should be familiar with the [Tor Project](https://www.torproject.org/) and the concept of an [onion service](https://www.torproject.org/docs/tor-onion-service.html.en).

There are two possible ways to serve Ergo over Tor. One is to add a .onion address to a server that also serves non-Tor clients, and whose IP address is public information. This is relatively straightforward. Add a separate listener, for example `127.0.0.2:6668`, to Ergo's `server.listeners`, then configure it with `tor: true`. Then configure Tor like this:

````
HiddenServiceDir /var/lib/tor/ergo_hidden_service
HiddenServicePort 6667 127.0.0.2:6668

# these are optional, but can be used to speed up the circuits in the case
# where the server's own IP is public information (clients will remain anonymous):
HiddenServiceNonAnonymousMode 1
HiddenServiceSingleHopMode 1
````

Tor provides end-to-end encryption for onion services, so there's no need to enable TLS in Ergo for the listener (`127.0.0.2:6668` in this example). Doing so is not recommended, given the difficulty in obtaining a TLS certificate valid for an .onion address.

The second way is to run Ergo as a true hidden service, where the server's actual IP address is a secret. This requires hardening measures on the Ergo side:

* Ergo should not accept any connections on its public interfaces. You should remove any listener that starts with the address of a public interface, or with `:`, which means "listen on all available interfaces". You should listen only on `127.0.0.1:6667` and a Unix domain socket such as `/hidden_service_sockets/ergo_tor_sock`.
* Push notifications will reveal the server's true IP address, so they must be disabled; set `webpush.enabled` to `false`.
* In this mode, it is especially important that all operator passwords are strong and all operators are trusted (operators have a larger attack surface to deanonymize the server).
* Onion services are at risk of being deanonymized if a client can trick the server into performing a non-Tor network request. Ergo should not perform any such requests (such as hostname resolution or ident lookups) in response to input received over a correctly configured Tor listener. However, Ergo has not been thoroughly audited against such deanonymization attacks --- therefore, Ergo should be deployed with additional sandboxing to protect against this:
  * Ergo should run with no direct network connectivity, e.g., by running in its own Linux network namespace. systemd implements this with the [PrivateNetwork](https://www.freedesktop.org/software/systemd/man/systemd.exec.html) configuration option: add `PrivateNetwork=true` to Ergo's systemd unit file.
  * Since the loopback adapters are local to a specific network namespace, and the Tor daemon will run in the root namespace, Tor will be unable to connect to Ergo over loopback TCP. Instead, Ergo must listen on a named Unix domain socket that the Tor daemon can connect to. However, distributions typically package Tor with its own hardening profiles, which restrict which sockets it can access. Below is a recipe for configuring this with the official Tor packages for Debian:

1. Create a directory with `0777` permissions such as `/hidden_service_sockets`.
1. Configure Ergo to listen on `/hidden_service_sockets/ergo_tor_sock`, with `tor: true`.
1. Ensure that Ergo has no direct network access as described above, e.g., with `PrivateNetwork=true`.
1. Next, modify Tor's apparmor profile so that it can connect to this socket, by adding the line `  /hidden_service_sockets/** rw,` to `/etc/apparmor.d/local/system_tor`.
1. Finally, configure Tor with:

````
HiddenServiceDir /var/lib/tor/ergo_hidden_service
HiddenServicePort 6667 unix:/hidden_service_sockets/ergo_tor_sock
# DO NOT enable HiddenServiceNonAnonymousMode
````

Instructions on how client software should connect to an .onion address are outside the scope of this manual. However:

1. [Hexchat](https://hexchat.github.io/) is known to support .onion addresses, once it has been configured to use a local Tor daemon as a SOCKS proxy (Settings -> Preferences -> Network Setup -> Proxy Server).
1. Pidgin should work with [torsocks](https://trac.torproject.org/projects/tor/wiki/doc/torsocks).

## I2P

I2P is an anonymizing overlay network similar to Tor. The recommended configuration for I2P is to treat it similarly to Tor: have the i2pd reverse proxy its connections to an Ergo listener configured with `tor: true`. See the [i2pd configuration guide](https://i2pd.readthedocs.io/en/latest/tutorials/irc/#running-anonymous-irc-server) for more details; note that the instructions to separate I2P traffic from other localhost traffic are unnecessary for a `tor: true` listener.

I2P can additionally expose an opaque client identifier (the user's "b32 address"). Exposing this identifier via Ergo is not recommended, but if you wish to do so, you can use the following procedure:

1. Enable WEBIRC support in the i2pd configuration by adding the `webircpassword` key to the [i2pd server block](https://i2pd.readthedocs.io/en/latest/tutorials/irc/#running-anonymous-irc-server)
1. Remove `tor: true` from the relevant Ergo listener config
1. Enable WEBIRC support in Ergo (starting from the default/recommended configuration, find the existing webirc block, delete the `certfp` configuration, change `password` to use the output of `ergo genpasswd` on the password you configured i2pd to send, and set `accept-hostname: true`)
1. To prevent Ergo from overwriting the hostname as passed from i2pd, set the following options: `server.ip-cloaking.enabled: false` and `server.lookup-hostnames: false`. (There is currently no support for applying cloaks to regular IP traffic but displaying the b32 address for I2P traffic).

## ZNC

ZNC 1.6.x (still pretty common in distros that package old versions of IRC software) has a [bug](https://github.com/znc/znc/issues/1212) where it fails to recognize certain SASL messages. Ergo supports a compatibility mode that works around this to let ZNC complete the SASL handshake: this can be enabled with `server.compatibility.send-unprefixed-sasl`.

Ergo can emulate certain capabilities of the ZNC bouncer for the benefit of clients, in particular the third-party [playback](https://wiki.znc.in/Playback) module. This enables clients with specific support for ZNC to receive selective history playback automatically. To configure this in [Textual](https://www.codeux.com/textual/), go to "Server properties", select "Vendor specific", uncheck "Do not automatically join channels on connect", and check "Only play back messages you missed". Other clients with support are listed on ZNC's wiki page.

## API

Ergo offers an HTTP API that can be used to control Ergo, or to allow other applications to use Ergo as a source of truth for authentication. The API is documented separately; see [API.md](https://github.com/ergochat/ergo/blob/stable/docs/API.md) on the website, or the `API.md` file that was bundled with your release.

## External authentication systems

Ergo can be configured to call arbitrary scripts to authenticate users; see the `auth-script` section of the config. The API for these scripts is as follows: Ergo will invoke the script with a configurable set of arguments, then send it the authentication data as JSON on the first line (`\n`-terminated) of stdin. The input is a JSON dictionary with the following keys:

* `accountName`: during passphrase-based authentication, this is a string, otherwise omitted
* `passphrase`: during passphrase-based authentication, this is a string, otherwise omitted
* `certfp`: during certfp-based authentication, this is a string, otherwise omitted
* `peerCerts`: during certfp-based authentication, this is a list of the PEM-encoded peer certificates (starting from the leaf), otherwise omitted
* `ip`: a string representation of the client's IP address

The script must print a single line (`\n`-terminated) to its output and exit. This line must be a JSON dictionary with the following keys:

* `success`, a boolean indicating whether the authentication was successful
* `accountName`, a string containing the normalized account name (in the case of passphrase-based authentication, it is permissible to return the empty string or omit the value)
* `error`, containing a human-readable description of the authentication error to be logged if applicable

Here is a toy example of an authentication script in Python that checks that the account name and the password are equal (and rejects any attempts to authenticate via certfp):

```python3
#!/usr/bin/python3

import sys, json

raw_input = sys.stdin.readline()
input = json.loads(raw_input)
account_name = input.get("accountName")
passphrase = input.get("passphrase")
success = bool(account_name) and bool(passphrase) and account_name == passphrase
print(json.dumps({"success": success}))
```

Note that after a failed script invocation, Ergo will proceed to check the credentials against its local database.

## DNSBLs and other IP checking systems

Similarly, Ergo can be configured to call arbitrary scripts to validate user IPs. These scripts can either reject the connection, or require that the user log in with SASL. In particular, we provide an [ergo-dnsbl](https://github.com/ergochat/ergo-dnsbl) plugin for querying DNSBLs.

The API is similar to the auth-script API described above (one line of JSON in, one line of JSON out). The input is a JSON dictionary with the following keys:

* `ip`: the IP in a standard human-readable notation, e.g., `1.1.1.1` or `2001::0db8`

The output is a JSON dictionary with the following keys:

* `result`: an integer indicating the result of the check (1 for "accepted", 2 for "banned", 3 for "SASL required")
* `banMessage`: a message to send to the user indicating why they are banned
* `error`, containing a human-readable description of the authentication error to be logged if applicable

--------------------------------------------------------------------------------------------


# Acknowledgements

Ergo's past and present maintainers and core contributors are:

* Jeremy Latt (2012-2014)
* Edmund Huber (2014-2015)
* Daniel Oaks (2016-present)
* Shivaram Lingamneni (2017-present)

In addition, Ergo has benefited tremendously from its community of contributors, users, and translators, not to mention collaborations with the wider IRCv3 community. There are too many people to name here --- but we try to credit people for individual contributions in the changelog, please reach out to us if we forgot you :-)
