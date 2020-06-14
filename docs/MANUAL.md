
          ▄▄▄   ▄▄▄·  ▄▄ •        ▐ ▄       
    ▪     ▀▄ █·▐█ ▀█ ▐█ ▀ ▪▪     •█▌▐█▪     
     ▄█▀▄ ▐▀▀▄ ▄█▀▀█ ▄█ ▀█▄ ▄█▀▄▪▐█▐▐▌ ▄█▀▄ 
    ▐█▌.▐▌▐█•█▌▐█ ▪▐▌▐█▄▪▐█▐█▌ ▐▌██▐█▌▐█▌.▐▌
     ▀█▄▀▪.▀  ▀ ▀  ▀ ·▀▀▀▀  ▀█▄▀ ▀▀ █▪ ▀█▄▀▪

           Oragono IRCd Manual v2.1.0
              https://oragono.io/

_Copyright © Daniel Oaks <daniel@danieloaks.net>, Shivaram Lingamneni <slingamn@cs.stanford.edu>_


--------------------------------------------------------------------------------------------


# Table of Contents

- Introduction
    - Project Basics
    - Scalability
- Installing
    - Windows
    - macOS / Linux / Raspberry Pi
    - Docker
    - Becoming an operator
    - Productionizing
    - Upgrading
- Features
    - User Accounts
        - Nickname reservation
        - Email verification
    - Channel Registration
    - Language
    - Multiclient ("Bouncer")
    - History
    - IP cloaking
- Frequently Asked Questions
- IRC over TLS
- Modes
    - User Modes
    - Channel Modes
    - Channel Prefixes
    - Client certificates
- Commands
- Working with other software
    - Kiwi IRC
    - HOPM
    - Tor
    - External authentication systems
- Acknowledgements


--------------------------------------------------------------------------------------------


# Introduction

This document goes over the Oragono IRC server, how to get it running and how to use it once it is up and running!

If you have any suggestions, issues or questions, feel free to submit an issue on our [GitHub repo](https://github.com/oragono/oragono/) or ask in our channel [`#oragono` on freenode](ircs://irc.freenode.net:6697/#oragono).


## Project Basics

Oragono is an ircd written "from scratch" in the [Go](https://en.wikipedia.org/wiki/Go_%28programming_language%29) language, i.e., it [shares no code](https://github.com/grawity/irc-docs/blob/master/family-tree.txt) with the original ircd implementation or any other major ircd. It began as [ergonomadic](https://github.com/jlatt/ergonomadic), which was developed by Jeremy Latt between 2012 and 2014. In 2016, Daniel Oaks forked the project under its current name Oragono, in order to prototype [IRCv3](https://ircv3.net/) features and for use as a reference implementation of the [Modern IRC specification](https://modern.ircdocs.horse). Oragono 1.0.0 was released in February 2019, and as of 2020 the project is under active development by multiple contributors.

Oragono's core design goals are:

* Being simple to set up and use
* Combining the features of an ircd, a services framework, and a bouncer (integrated account management, history storage, and bouncer functionality)
* Bleeding-edge [IRCv3 support](http://ircv3.net/software/servers.html), suitable for use as an IRCv3 reference implementation
* Highly customizable via a rehashable (i.e., reloadable at runtime) YAML config

In addition to its unique features (integrated services and bouncer, comprehensive internationalization), Oragono also strives for feature parity with other major servers. Oragono is a mature project with multiple communities using it as a day-to-day chat server --- we encourage you to consider it for your organization or community!

## Scalability

We believe Oragono should scale comfortably to 10,000 clients and 2,000 clients per channel, making it suitable for small to medium-sized teams and communities. Oragono does not currently support server-to-server linking (federation), meaning that all clients must connect to the same instance. However, since Oragono is implemented in Go, it is reasonably effective at distributing work across multiple cores on a single server; in other words, it should "scale up" rather than "scaling out". (Federation is [planned](https://github.com/oragono/oragono/issues/26) but is not scheduled for development in the near term.)

Even though it runs as a single instance, Oragono can be deployed for high availability (i.e., with no single point of failure) using Kubernetes. This technique uses a k8s [LoadBalancer](https://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/) to receive external traffic and a [Volume](https://kubernetes.io/docs/concepts/storage/volumes/) to store the embedded database file.

If you're interested in deploying Oragono at scale or for high availability, or want performance tuning advice, come find us on [`#oragono` on freenode](ircs://irc.freenode.net:6697/#oragono), we're very interested in what our software can do!


--------------------------------------------------------------------------------------------


# Installing

In this section, we'll explain how to install and use the Oragono IRC server.


## Windows

To get started with Oragono on Windows:

1. Make sure you have the [latest release](https://github.com/oragono/oragono/releases/latest) downloaded.
1. Extract the zip file to a folder.
1. Copy and rename `default.yaml` to `ircd.yaml`.
1. Open up `ircd.yaml` using any text editor, and then save it once you're happy.
1. Open up a `cmd.exe` window, then `cd` to where you have Oragono extracted.
1. Run `oragono.exe mkcerts` if you want to generate new self-signed SSL/TLS certificates (note that you can't enable STS if you use self-signed certs).

To start the server, type `oragono.exe run` and hit enter, and the server should start!


## macOS / Linux / Raspberry Pi

To get started with Oragono on macOS, Linux, or on a Raspberry Pi:

1. Make sure you have the [latest release](https://github.com/oragono/oragono/releases/latest) for your OS/distro downloaded.
1. Extract the tar.gz file to a folder.
1. Copy and rename `default.yaml` to `ircd.yaml`.
1. Open up `ircd.yaml` using any text editor, and then save it once you're happy.
1. Open up a Terminal window, then `cd` to where you have Oragono extracted.
1. Run `./oragono mkcerts` if you want to generate new self-signed SSL/TLS certificates (note that you can't enable STS if you use self-signed certs).

To start the server, type `./oragono run` and hit enter, and the server should be ready to use!

If you're using Arch Linux, you can also install the [`oragono` package](https://aur.archlinux.org/packages/oragono/) from the AUR.


## Docker

1. Pull the latest version of Oragono: `docker pull oragono/oragono:latest`
1. Create a volume for persistent data: `docker volume create oragono-data`
1. Run the container, exposing the default ports: `docker run -d --name oragono -v oragono-data:/ircd-data -p 6667:6667 -p 6697:6697 oragono/oragono:latest`

For further information and a sample docker-compose file see the separate [Docker documentation](https://github.com/oragono/oragono/blob/master/distrib/docker/README.md).


## Becoming an operator

Many administrative actions on an IRC server are performed "in-band" as IRC commands sent from a client. The client in question must be an IRC operator ("oper", "ircop"). The easiest way to become an operator on your new Oragono instance is first to pick a strong, secure password, then "hash" it using the `oragono genpasswd` command (run `oragono genpasswd` from the command line, then enter your password twice), then copy the resulting hash into the `opers` section of your `ircd.yaml` file. Then you can become an operator by issuing the IRC command: `/oper admin mysecretpassword`.


## Productionizing

The recommended way to operate oragono as a service on Linux is via systemd. This provides a standard interface for starting, stopping, and rehashing (via `systemctl reload`) the service. It also captures oragono's loglines (sent to stderr in the default configuration) and writes them to the system journal.

The only major distribution that currently packages Oragono is Arch Linux; the aforementioned AUR package includes a systemd unit file. However, it should be fairly straightforward to set up a productionized Oragono on any Linux distribution. Here's a quickstart guide for Debian/Ubuntu:

1. Create a dedicated, unprivileged role user who will own the oragono process and all its associated files: `adduser --system --group oragono`. This user now has a home directory at `/home/oragono`.
1. Copy the executable binary `oragono`, the config file `ircd.yaml`, the database `ircd.db`, and the self-signed TLS certificate (`fullchain.pem` and `privkey.pem`) to `/home/oragono`. Ensure that they are all owned by the new oragono role user: `sudo chown oragono:oragono /home/oragono/*`. Ensure that the configuration file logs to stderr.
1. Install our example [oragono.service](https://github.com/oragono/oragono/blob/master/distrib/systemd/oragono.service) file to `/etc/systemd/system/oragono.service`.
1. Enable and start the new service with the following commands:
    1. `systemctl daemon-reload`
    1. `systemctl enable oragono.service`
    1. `systemctl start oragono.service`
    1. Confirm that the service started correctly with `systemctl status oragono.service`

The other major hurdle for productionizing (but one well worth the effort) is obtaining valid TLS certificates for your domain, if you haven't already done so:

1. The simplest way to get valid TLS certificates is from [Let's Encrypt](https://letsencrypt.org/) with [Certbot](https://certbot.eff.org/). The correct procedure will depend on whether you are already running a web server on port 80. If you are, follow the guides on the Certbot website; if you aren't, you can use `certbot certonly --standalone --preferred-challenges http -d example.com` (replace `example.com` with your domain).
1. At this point, you should have certificates available at `/etc/letsencrypt/live/example.com` (replacing `example.com` with your domain). You should serve `fullchain.pem` as the certificate and `privkey.pem` as its private key. However, these files are owned by root and the private key is not readable by the oragono role user, so you won't be able to use them directly in their current locations. You can write a post-renewal hook for certbot to make copies of these certificates accessible to the oragono role user. For example, install the following script as `/etc/letsencrypt/renewal-hooks/post/install-oragono-certificates`, again replacing `example.com` with your domain name, and chmod it 0755:

````bash
#!/bin/bash

set -eu

umask 077
cp /etc/letsencrypt/live/example.com/fullchain.pem /home/oragono/
cp /etc/letsencrypt/live/example.com/privkey.pem /home/oragono/
chown oragono:oragono /home/oragono/*.pem
# rehash oragono, which will reload the certificates:
systemctl reload oragono.service
````

Executing this script manually will install the certificates for the first time and perform a rehash, enabling them.

If you are using Certbot 0.29.0 or higher, you can also change the ownership of the files under `/etc/letsencrypt` so that the oragono user can read them, as described in the [UnrealIRCd documentation](https://www.unrealircd.org/docs/Setting_up_certbot_for_use_with_UnrealIRCd#Tweaking_permissions_on_the_key_file).

On a non-systemd system, oragono can be configured to log to a file and used [logrotate(8)](https://linux.die.net/man/8/logrotate), since it will reopen its log files (as well as rehashing the config file) upon receiving a SIGHUP. To rehash manually outside the context of log rotation, you can use `killall -HUP oragono` or `pkill -HUP oragono`.


## Upgrading to a new version of Oragono

As long as you are using official releases or release candidates of Oragono, any backwards-incompatible changes should be described in the changelog.

In general, the config file format should be fully backwards and forwards compatible. Unless otherwise noted, no config file changes should be necessary when upgrading Oragono. However, the "config changes" section of the changelog will typically describe new sections that can be added to your config to enable new functionality, as well as changes in the recommended values of certain fields.

The database is versioned; upgrades that involve incompatible changes to the database require updating the database. If you have `datastore.autoupgrade` enabled in your config, the database will be backed up and upgraded when you restart your server when required. Otherwise, you can apply upgrades manually:

1. Stop your server
1. Make a backup of your database file
1. Run `oragono upgradedb` (from the same working directory and with the same arguments that you would use when running `oragono run`)
1. Start the server again

If you want to run our master branch as opposed to our releases, come find us in our channel and we can guide you around any potential pitfalls.


--------------------------------------------------------------------------------------------


# Features

In this section, we'll explain and go through using various features of the Oragono IRC server.


## User Accounts

In most IRC servers you can use `NickServ` to register an account. You can do the same thing with Oragono, by default, with no other software needed!

To register an account, use:

    /NS REGISTER <password>

This is the way to go if you want to use a regular password. `<password>` is your password, your current nickname will become your username. Your password cannot contain spaces, but make sure to use a strong one anyway.

If you want to use a TLS client certificate instead of a password to authenticate (`SASL EXTERNAL`), then you can use the command below to do so. (If you're not sure what this is, don't worry – just use the above password method to register an account.)

    /NS REGISTER *

Once you've registered, you'll need to setup SASL to login (or use NickServ IDENTIFY). One of the more complete SASL instruction pages is Freenode's page [here](https://freenode.net/kb/answer/sasl). Open up that page, find your IRC client and then setup SASL with your chosen username and password!

## Account/Nick Modes

Oragono supports several different modes of operation with respect to accounts and nicknames.

### Traditional / lenient mode

This makes Oragono's services act similar to Quakenet's Q bot. In this mode, users cannot own or reserve nicknames. In other words, there is no connection between account names and nicknames. Anyone can use any nickname (as long as it's not already in use by another running client). However, accounts are still useful: they can be used to register channels (see below), and some IRCv3-capable clients (with the `account-tag` or `extended-join` capabilities) may be able to take advantage of them.

To enable this mode, set the following configs:

* `accounts.registration.enabled = true`
* `accounts.authentication-enabled = true`
* `accounts.nick-reservation.enabled = false`

### Nick ownership

In this mode (the default), registering an account gives you privileges over the use of that account as a nickname. The server will then help you to enforce control over your nickname(s). No one will be able to use your nickname unless they are logged into your account.

To enable this mode, set the following configs:

* `accounts.registration.enabled = true`
* `accounts.authentication-enabled = true`
* `accounts.nick-reservation.enabled = true`
* `accounts.nick-reservation.method = strict`

The following additional configs may be of interest:

* `accounts.nick-reservation.force-nick-equals-account = true` ; this allows nicknames to be treated as account names for most purposes, including for controlling access to channels (see the discussion of private channels below)

### SASL-only mode

This mode is comparable to Slack, Mattermost, or similar products intended as internal chat servers for an organization or team. In this mode, clients cannot connect to the server unless they log in with SASL as part of the initial handshake. This allows Oragono to be deployed facing the public Internet, with fine-grained control over who can log in.

In this mode, clients must have a valid account to connect, so they cannot register their own accounts. Accordingly, an operator must do the initial account creation, using the `SAREGISTER` command of NickServ. (For more details, `/msg NickServ help saregister`.) To bootstrap this process, you can make an initial connection from localhost, which is exempt (by default) from the requirement, or temporarily add your own IP to the exemption list. You can also use a more permissive configuration for bootstrapping, then switch to this one once you have your account. Another possibility is permanently exempting an internal network, e.g., `10.0.0.0/8`, that only trusted people can access.

To enable this mode, set the following configs:

* `accounts.registration.enabled = false`
* `accounts.authentication-enabled = true`
* `accounts.require-sasl.enabled = true`
* `accounts.nick-reservation.enabled = true`
* `accounts.nick-reservation.method = strict`
* `accounts.nick-reservation.force-nick-equals-account = true`

### Email verification

By default, account registrations complete immediately and do not require a verification step. However, like other service frameworks, Oragono's NickServ can be configured to require email verification of registrations. The main challenge here is to prevent your emails from being marked as spam, which you can do by configuring [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework), [DKIM](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail), and [DMARC](https://en.wikipedia.org/wiki/DMARC). For example, this configuration (when added to the `accounts.registration` section) enables email verification, with the emails being signed with a DKIM key and sent directly from Oragono:

```yaml
        enabled-callbacks:
            - mailto

        callbacks:
            mailto:
                sender: "admin@my.network"
                require-tls: true
                dkim:
                    domain: "my.network"
                    selector: "20200525"
                    key-file: "dkim-private-20200525.pem"
```

You must create the corresponding TXT record `20200525._domainkey.my.network` to hold your public key. You can also use an MTA ("relay" or "smarthost") to send the email, in which case DKIM signing can be deferred to the MTA; see the example config for details.


## Channel Registration

Once you've registered an account, you can also register channels. If you own a channel, you'l be opped whenever you join it, and the topic/modes will be remembered and re-applied whenever anyone rejoins the channel.

To register a channel, make sure you're joined to it and logged into your account. If both those are true, you can send this command to register your account:

    /CS REGISTER #channelname

For example, `/CS REGISTER #channel` will register the channel `#test` to my account. If you have a registered channel, you can use `/CS OP #channel` to regain ops in it. Right now, the options for a registered channel are pretty sparse, but we'll add more as we go along.

If your friends have registered accounts, you can automatically grant them operator permissions when they join the channel. For more details, see `/CS HELP AMODE`.


## Language

Oragono supports multiple languages! Specifically, once you connect you're able to get server messages in other languages (messages from other users will still be in their original languages, though).

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

Our language and translation functionality is very early, so feel free to let us know if there are any troubles with it! If you know another language and you'd like to contribute, we've got a CrowdIn project here: [https://crowdin.com/project/oragono](https://crowdin.com/project/oragono)


## Multiclient ("Bouncer")

Traditionally, every connection to an IRC server is separate must use a different nickname. [Bouncers](https://en.wikipedia.org/wiki/BNC_%28software%29#IRC) are used to work around this, by letting multiple clients connect to a single nickname. With Oragono, if the server is configured to allow it, multiple clients can share a single nickname without needing a bouncer. To use this feature, both connections must authenticate with SASL to the same user account and then use the same nickname during connection registration (while connecting to the server) – once you've logged-in, you can't share another nickname.

To enable this functionality, set `accounts.multiclient.enabled` to `true`. Setting `accounts.multiclient.allowed-by-default` to `true` will allow this for everyone. If `allowed-by-default` is `false` (but `enabled` is still `true`), users can opt in to shared connections using `/msg NickServ SET multiclient true`.

You can see a list of your active sessions and their idle times with `/msg NickServ sessions` (network operators can use `/msg NickServ sessions nickname` to see another user's sessions).

Oragono now supports "always-on clients" that remain present on the server (holding their nickname, subscribed to channels, able to receive DMs, etc.) even when no actual clients are connected. To enable this as a server operator, set `accounts.multiclient.always-on` to either `opt-in`, `opt-out`, or `mandatory`. To enable or disable it as a client (if the server setting is `opt-in` or `opt-out` respectively), use `/msg NickServ set always-on true` (or `false`).


## History

Oragono supports two methods of storing history, an in-memory buffer with a configurable maximum number of messages, and persistent history stored in MySQL (with no fixed limits on message capacity). To enable in-memory history, configure `history.enabled` and associated settings in the `history` section. To enable persistent history, enter your MySQL server information in `datastore.mysql` and then enable persistent history storage in `history.persistent`.

Unfortunately, client support for history playback is still patchy. In descending order of support:

1. The [IRCv3 chathistory specification](https://github.com/ircv3/ircv3-specifications/pull/393/) offers the most fine-grained control over history replay. It is supported by [Kiwi IRC](https://github.com/kiwiirc/kiwiirc), and hopefully other clients soon.
1. We emulate the [ZNC playback module](https://wiki.znc.in/Playback) for clients that support it. You may need to enable support for it explicitly in your client (see the "ZNC" section below).
1. If you are not using the multiclient functionality, but your client is set to be always-on (see the previous section for details), Oragono will remember the last time your client signed out. You can then set your account to replay only messages you missed with `/msg NickServ set autoreplay-missed on`. Unfortunately, this feature will only work reliably if you are *not* using the multiclient functionality described in the above section --- you must be connecting with at most one client at a time.
1. You can manually request history using `/history #channel 1h` (the parameter is either a message count or a time duration). (Depending on your client, you may need to use `/QUOTE history` instead.)
1. You can autoreplay a fixed number of lines (e.g., 25) each time you join a channel using `/msg NickServ set autoreplay-lines 25`.


## IP cloaking

Unlike many other chat and web platforms, IRC traditionally exposes the user's IP and hostname information to other users. This is in part because channel owners and operators (who have privileges over a single channel, but not over the server as a whole) need to be able to ban spammers and abusers from their channels, including via hostnames in cases where the abuser tries to evade the ban.

IP cloaking is a way of balancing these concerns about abuse with concerns about user privacy. With cloaking, the user's IP address is deterministically "scrambled", typically via a cryptographic [MAC](https://en.wikipedia.org/wiki/Message_authentication_code), to form a "cloaked" hostname that replaces the usual reverse-DNS-based hostname. Users cannot reverse the scrambling to learn each other's IPs, but can ban a scrambled address the same way they would ban a regular hostname.

Oragono supports cloaking, which is enabled by default (via the `server.ip-cloaking` section of the config). However, Oragono's cloaking behavior differs from other IRC software. Rather than scrambling each of the 4 bytes of the IPv4 address (or each 2-byte pair of the 8 such pairs of the IPv6 address) separately, the server administrator configures a CIDR length (essentially, a fixed number of most-significant-bits of the address). The CIDR (i.e., only the most significant portion of the address) is then scrambled atomically to produce the cloaked hostname. This errs on the side of user privacy, since knowing the cloaked hostname for one CIDR tells you nothing about the cloaked hostnames of other CIDRs --- the scheme reveals only whether two users are coming from the same CIDR. We suggest using 32-bit CIDRs for IPv4 (i.e., the whole address) and 64-bit CIDRs for IPv6, since these are the typical assignments made by ISPs to individual customers.

Setting `server.ip-cloaking.num-bits` to 0 gives users cloaks that don't depend on their IP address information at all, which is an option for deployments where privacy is a more pressing concern than abuse. Holders of registered accounts can also use the vhost system (for details, `/msg HostServ HELP`.)

-------------------------------------------------------------------------------------------


# Frequently Asked Questions

Some troubleshooting, some general questions about the project! This should help answer any sorta queries you have.


## I have a suggestion

Awesome! We love getting new suggestions for features, ways to improve the server and the tooling around it, everything.

There are two ways to make suggestions, either:

- Submit an issue on our [bug tracker](https://github.com/oragono/oragono/issues).
- Talk to us in the `#oragono` channel on Freenode.


## Why can't I oper?

If you try to oper unsuccessfully, Oragono will disconnect you from the network. Here's some important things to try if you find yourself unable to oper:

1. Have you generated the config-file password blob with `oragono genpasswd`?
2. Have you restarted Oragono to make sure the new password has taken effect?
3. If all else fails, can you get raw protocol output from Oragono for evaluation?

So, first off you'll want to make sure you've stored the password correctly. In the config file, all passwords are bcrypted. Basically, you run `oragono genpasswd`, type your actual password in, and then receive a config file blob back. Put that blob into the config file, and then use the actual password in your IRC client.

After that, try restarting Oragono to see if that improves things. Even if you've already done so or already rehashed, a proper restart can sometimes help things. Make sure your config file is saved before restarting the server.

If both of those have failed, it might be worth getting us to look at the raw lines and see what's up.

If you're familiar with getting this output through your client (e.g. in weechat it's `/server raw`) then you can do so that way, or use [ircdog](https://github.com/goshuirc/ircdog).

Otherwise, in the Oragono config file, you'll want to enable raw line logging by removing `-userinput -useroutput` under the `logging` section. Once you start up your server, connect, fail to oper and get disconnected, you'll see a bunch of input/output lines in Ora's log file. Remove your password from those logs and pass them our way.

## How do I make a private channel?

We recommend that server administrators set the following recommended defaults:

1. `nick-reservation-method: strict`
1. `force-nick-equals-account: true`

These settings imply that any registered account name can be treated as synonymous with a nickname; anyone using the nickname is necessarily logged into the account, and anyone logged intot he account is necessarily using the nickname.

Under these circumstances, users can follow the following steps:

1. Register a channel (`/msg ChanServ register #example`)
1. Set it to be invite-only (`/mode #example +i`)
1. Add the desired nick/account names to the invite exception list (`/mode #example +I alice`)
1. Anyone with persistent half-operator status or higher will also be able to join without an invite (`/msg ChanServ amode #example +h alice`)

Similarly, for a public channel (one without `+i`), users can ban nick/account names with `/mode #example +b bob`. (To restrict the channel to users with valid accounts, set it to registered-only with `/mode #example +R`.)

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

You may want to configure a reverse proxy, such as nginx, for TLS termination --- for example, because you need to support versions of the TLS protocol that are not implemented natively by Go, or because you want to consolidate your certificate management into a single nginx instance. Oragono supports the [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) for preserving the end user's IP in this case. To configure a reverse proxy, use the following steps:

1. Add the reverse proxy's IP to `proxy-allowed-from` and `ip-limits.exempted`. (Use `localhost` to exempt all loopback IPs and Unix domain sockets.)
1. Configure your reverse proxy to connect to an appropriate Oragono listener and send the PROXY line. In this [example nginx config](https://github.com/darwin-network/slash/commit/aae9ba08d70128eb4b700cade333fe824a53562d), nginx connects to Oragono via a Unix domain socket.

## Client certificates

Oragono supports authenticating to user accounts via TLS client certificates. The end user must enable the client certificate in their client and also enable SASL with the `EXTERNAL` method. To register an account using only a client certificate for authentication, connect with the client certificate and use `/NS REGISTER *` (or `/NS REGISTER * email@example.com` if email verification is enabled on the server). To add a client certificate to an existing account, obtain the SHA-256 fingerprint of the certificate (either by connecting with it and looking at your own `/WHOIS` response, in particular the `276 RPL_WHOISCERTFP` line, or using the openssl command `openssl x509 -noout -fingerprint -sha256 -in example_client_cert.pem`), then use the `/NS CERT` command).

Client certificates are not supported over websockets due to a [Chrome bug](https://bugs.chromium.org/p/chromium/issues/detail?id=329884).


--------------------------------------------------------------------------------------------


# Modes

On IRC, you can set modes on users and on channels. Modes are basically extra information that changes how users and channels work.

In this section, we give an overview of the modes Oragono supports.


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


## Channel Modes

These are the modes that can be set on channels when you're an oper!

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

### +e - Ban-Exempt

With this channel mode, you can change who's allowed to bypass bans. For example, let's say you set these modes on the channel:

    /MODE #test +b *!*@192.168.0.234
    /MODE #test +e bob!*@*

This means that **bob** will always be able to join, even if he's connecting from `192.168.0.234`.

For everything else, this mode acts like the `+b - Ban` mode.

### +i - Invite-Only

If this channel mode is set on a channel, users will only be able to join if someone has `/INVITE`'d them first.

To set a channel to invite-only:

    /MODE #test +i

To unset the mode and let anyone join:

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

### +R - Registered Only

If this mode is set, only users that have logged into an account will be able to join and speak on the channel. If this is set and a regular, un-logged-in user tries to join, they will be rejected.

To set this mode:

    /MODE #test +R

To unset this mode:

    /MODE #test -R

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


## Channel Prefixes

Users on a channel can have different permission levels, which are represented by having different characters in front of their nickname. This section explains the prefixes and what each one means.

### +q (~) - Founder

This prefix means that the given user is the founder of the channel. For example, if `~dan` is on a channel it means that **dan** founded the channel. The 'founder' prefix only appears on channels that are registered.

Founders are able to do anything, and have complete administrative control of the channel.

### +a (&) - Admin

This prefix means that the given user is an admin on the channel. For example, if `&tom` is on a channel, then **tom** is an admin on it. The 'admin' prefix only appears on channels that are registered.

Admins can do anything channel operators can do, and they also cannot get kicked by other chanops or admins.

### +o (@) - Channel Operator

This prefix means that the given user is an operator on the channel (chanop, for short). For example, if `@ruby` is on a channel, then **ruby** is an op.

Chanops are the regular type of channel moderators. They can set the topic, change modes, ban/kick users, etc.

### +h (%) - Halfop

This prefix means that the given user is a halfop on the channel (half-operator). For example, if `%twi` is on a channel, then **twi** is a halfop.

Halfops can do some of what channel operators can do, and can't do other things. They can help moderate a channel.

### +v (+) - Voice

This prefix means that the given user is 'voiced' on the channel. For example, if `+faust` is on a channel, then **faust** is voiced on that channel.

Voiced users can speak when the channel has `+m - Moderated` mode enabled. They get no other special privs or any moderation abilities.


--------------------------------------------------------------------------------------------


# Commands

The best place to look for command help is on a running copy or Oragono itself!

To see the integrated command help, simply spin up a copy of Oragono and then run this command:

    /HELPOP <command>

If that doesn't work, you may need to run this instead:

    /QUOTE HELP <command>

We may add some additional notes here for specific commands down the line, but right now the in-server docs are the best ones to consult.


--------------------------------------------------------------------------------------------


# Working with other software

Oragono should interoperate with most IRC-based software, including bots. If you have problems getting your preferred software to work with Oragono, feel free to report it to us. If the root cause is a bug in Oragono, we'll fix it.

One exception is services frameworks like [Anope](https://github.com/anope/anope) or [Atheme](https://github.com/atheme/atheme); we have our own services implementations built directly into the server, and since we don't support federation, there's no place to plug in an alternative implementation.

If you're looking for a bot that supports modern IRCv3 features, check out [bitbot](https://github.com/jesopo/bitbot/)!

## Kiwi IRC

[Kiwi IRC](https://github.com/kiwiirc/kiwiirc/) is a web-based IRC client with excellent IRCv3 support. In particular, it is the only major client to fully support Oragono's server-side history features. For a demonstration of these features, see the [Oragono testnet](https://testnet.oragono.io/kiwi).

Current versions of Kiwi are 100% static files (HTML and Javascript), running entirely in the end user's browser without the need for a separate server-side backend. This frontend can connect directly to Oragono, using Oragono's support for native websockets. For best interoperability with firewalls, you should run an externally facing web server on port 443 that can serve both the static files and the websocket path, then have it reverse-proxy the websocket path to Oragono. For example, configure the following listener in ircd.yaml:

```yaml
        "127.0.0.1:8067":
            websocket: true
```

then the following location block in your nginx config (this proxies only `/webirc` on your server to Oragono's websocket listener):

```
	location /webirc {
		proxy_pass http://127.0.0.1:8067;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection "Upgrade";
		proxy_set_header X-Forwarded-For $remote_addr;
		proxy_set_header X-Forwarded-Proto $scheme;
	}
```

then add the following `startupOptions` to Kiwi's `static/config.json` file (see the [Oragono testnet's config.json](https://testnet.oragono.io/kiwi/static/config.json) for a fully functional example):

```
    "startupOptions" : {
        "websocket": "wss://domain.example.com/webirc",
        "channel": "#chat",
        "nick": "kiwi-n?"
    },
```

## Hybrid Open Proxy Monitor (HOPM)

[hopm](https://github.com/ircd-hybrid/hopm) can be used to monitor your server for connections from open proxies, then automatically ban them. To configure hopm to work with oragono, add operator blocks like this to your oragono config file, which grant hopm the necessary privileges:

````yaml
# operator classes
oper-classes:
    # hopm
    "hopm":
        # title shown in WHOIS
        title: Proxy Monitor

        # capability names
        capabilities:
        - "local_kill"
        - "local_ban"
        - "local_unban"
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
        # generated using  "oragono genpasswd"
        password: "$2a$04$JmsYDY6kX3/wwyK3ao0L7.aGJEto0Xm4DyL6/6zOmCpzeweIb8kdO"
````

Then configure hopm like this:

````
/* oragono */
connregex = ".+-.+CONNECT.+-.+ Client Connected \\[([^ ]+)\\] \\[u:([^ ]+)\\] \\[h:([^ ]+)\\] \\[ip:([^ ]+)\\] .+";

/* A DLINE example for oragono */
kline = "DLINE ANDKILL 2h %i :Open proxy found on your host.";
````

## Tor

Oragono has code support for adding an .onion address to an IRC server, or operating an IRC server as a Tor onion service ("hidden service"). This is subtle, so you should be familiar with the [Tor Project](https://www.torproject.org/) and the concept of an [onion service](https://www.torproject.org/docs/tor-onion-service.html.en).

There are two possible ways to serve Oragono over Tor. One is to add a .onion address to a server that also serves non-Tor clients, and whose IP address is public information. This is relatively straightforward. Add a separate listener, for example `127.0.0.2:6668`, to Oragono's `server.listeners`, then configure it with `tor: true`. Then configure Tor like this:

````
HiddenServiceDir /var/lib/tor/oragono_hidden_service
HiddenServicePort 6667 127.0.0.2:6668

# these are optional, but can be used to speed up the circuits in the case
# where the server's own IP is public information (clients will remain anonymous):
HiddenServiceNonAnonymousMode 1
HiddenServiceSingleHopMode 1
````

Tor provides end-to-end encryption for onion services, so there's no need to enable TLS in Oragono for the listener (`127.0.0.2:6668` in this example). Doing so is not recommended, given the difficulty in obtaining a TLS certificate valid for an .onion address.

The second way is to run Oragono as a true hidden service, where the server's actual IP address is a secret. This requires hardening measures on the Oragono side:

* Oragono should not accept any connections on its public interfaces. You should remove any listener that starts with the address of a public interface, or with `:`, which means "listen on all available interfaces". You should listen only on `127.0.0.1:6667` and a Unix domain socket such as `/hidden_service_sockets/oragono.sock`.
* In this mode, it is especially important that all operator passwords are strong and all operators are trusted (operators have a larger attack surface to deanonymize the server).
* Onion services are at risk of being deanonymized if a client can trick the server into performing a non-Tor network request. Oragono should not perform any such requests (such as hostname resolution or ident lookups) in response to input received over a correctly configured Tor listener. However, Oragono has not been thoroughly audited against such deanonymization attacks --- therefore, Oragono should be deployed with additional sandboxing to protect against this:
  * Oragono should run with no direct network connectivity, e.g., by running in its own Linux network namespace. systemd implements this with the [PrivateNetwork](https://www.freedesktop.org/software/systemd/man/systemd.exec.html) configuration option: add `PrivateNetwork=true` to Oragono's systemd unit file.
  * Since the loopback adapters are local to a specific network namespace, and the Tor daemon will run in the root namespace, Tor will be unable to connect to Oragono over loopback TCP. Instead, Oragono must listen on a named Unix domain socket that the Tor daemon can connect to. However, distributions typically package Tor with its own hardening profiles, which restrict which sockets it can access. Below is a recipe for configuring this with the official Tor packages for Debian:

1. Create a directory with `0777` permissions such as `/hidden_service_sockets`.
1. Configure Oragono to listen on `/hidden_service_sockets/oragono.sock`, and add this socket to `server.tor-listeners.listeners`.
1. Ensure that Oragono has no direct network access as described above, e.g., with `PrivateNetwork=true`.
1. Next, modify Tor's apparmor profile so that it can connect to this socket, by adding the line `  /hidden_service_sockets/** rw,` to `/etc/apparmor.d/local/system_tor`.
1. Finally, configure Tor with:

````
HiddenServiceDir /var/lib/tor/oragono_hidden_service
HiddenServicePort 6667 unix:/hidden_service_sockets/oragono.sock
# DO NOT enable HiddenServiceNonAnonymousMode
````

Instructions on how client software should connect to an .onion address are outside the scope of this manual. However:

1. [Hexchat](https://hexchat.github.io/) is known to support .onion addresses, once it has been configured to use a local Tor daemon as a SOCKS proxy (Settings -> Preferences -> Network Setup -> Proxy Server).
1. Pidgin should work with [torsocks](https://trac.torproject.org/projects/tor/wiki/doc/torsocks).


## ZNC

ZNC 1.6.x (still pretty common in distros that package old versions of IRC software) has a [bug](https://github.com/znc/znc/issues/1212) where it fails to recognize certain SASL messages. Oragono supports a compatibility mode that works around this to let ZNC complete the SASL handshake: this can be enabled with `server.compatibility.send-unprefixed-sasl`.

Oragono can emulate certain capabilities of the ZNC bouncer for the benefit of clients, in particular the third-party [playback](https://wiki.znc.in/Playback) module. This enables clients with specific support for ZNC to receive selective history playback automatically. To configure this in [Textual](https://www.codeux.com/textual/), go to "Server properties", select "Vendor specific", uncheck "Do not automatically join channels on connect", and check "Only play back messages you missed". Other clients with support are listed on ZNC's wiki page.

## External authentication systems

Oragono can be configured to call arbitrary scripts to authenticate users; see the `auth-script` section of the config. The API for these scripts is as follows: Oragono will invoke the script with a configurable set of arguments, then send it the authentication data as JSON on the first line (`\n`-terminated) of stdin. The input is a JSON dictionary with the following keys:

* `accountName`: during passphrase-based authentication, this is a string, otherwise omitted
* `passphrase`: during passphrase-based authentication, this is a string, otherwise omitted
* `certfp`: during certfp-based authentication, this is a string, otherwise omitted
* `ip`: a string representation of the client's IP address

The script must print a single line (`\n`-terminated) to its output and exit. This line must be a JSON dictionary with the following keys:

* `success`, a boolean indicating whether the authentication was successful
* `accountName`, a string containing the normalized account name (in the case of passphrase-based authentication, it is permissible to return the empty string or omit the value)
* `error`, containing a human-readable description of the authentication error to be logged if applicable

Here is a toy example of an authentication script in Python that checks that the account name and the password are equal (and rejects any attempts to authenticate via certfp):

```
#!/usr/bin/python3

import sys, json

raw_input = sys.stdin.readline()
input = json.loads(b)
account_name = input.get("accountName")
passphrase = input.get("passphrase")
success = bool(account_name) and bool(passphrase) and account_name == passphrase
print(json.dumps({"success": success})
```

Note that after a failed script invocation, Oragono will proceed to check the credentials against its local database.


--------------------------------------------------------------------------------------------


# Acknowledgements

Oragono's past and present maintainers and core contributors are:

* Jeremy Latt (2012-2014)
* Edmund Huber (2014-2015)
* Daniel Oaks (2016-present)
* Shivaram Lingamneni (2017-present)

In addition, Oragono has benefited tremendously from its community of contributors, users, and translators, not to mention collaborations with the wider IRCv3 community. There are too many people to name here --- but we try to credit people for individual contributions in the changelog, please reach out to us if we forgot you :-)
