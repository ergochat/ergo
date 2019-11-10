
          ▄▄▄   ▄▄▄·  ▄▄ •        ▐ ▄       
    ▪     ▀▄ █·▐█ ▀█ ▐█ ▀ ▪▪     •█▌▐█▪     
     ▄█▀▄ ▐▀▀▄ ▄█▀▀█ ▄█ ▀█▄ ▄█▀▄▪▐█▐▐▌ ▄█▀▄ 
    ▐█▌.▐▌▐█•█▌▐█ ▪▐▌▐█▄▪▐█▐█▌ ▐▌██▐█▌▐█▌.▐▌
     ▀█▄▀▪.▀  ▀ ▀  ▀ ·▀▀▀▀  ▀█▄▀ ▀▀ █▪ ▀█▄▀▪

         Oragono IRCd Manual 2019-06-12
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
    - Upgrading
- Features
    - User Accounts
        - Nickname reservation
    - Channel Registration
    - Language
    - Bouncer
    - History
    - IP cloaking
- Frequently Asked Questions
- IRC over TLS
- Modes
    - User Modes
    - Channel Modes
    - Channel Prefixes
- Commands
- Working with other software
    - HOPM
    - Tor
- Acknowledgements


--------------------------------------------------------------------------------------------


# Introduction

This document goes over the Oragono IRC server, how to get it running and how to use it once it is up and running!

If you have any suggestions, issues or questions, feel free to submit an issue on our [GitHub repo](https://github.com/oragono/oragono/) or ask in our channel [`#oragono` on freenode](ircs://irc.freenode.net:6697/#oragono).


## Project Basics

Let's go over some basics, for those new to Oragono. My name's Daniel, and I started the project (it was forked off a server called [Ergonomadic](https://github.com/edmund-huber/ergonomadic) that'd been around for a number of years). In addition to Oragono, I also do a lot of IRC specification work with the [various](https://modern.ircdocs.horse) [ircdocs](https://defs.ircdocs.horse) [projects](https://ircdocs.horse/specs/) and with the [IRCv3 Working Group](https://ircv3.net/).

My main goals when starting the project were to write a server that:

- Is fully-functional.
- I can use to very easily prototype new [IRCv3](https://ircv3.net/) proposals and features.
- I can consider a reference implementation for the [Modern spec](https://modern.ircdocs.horse).

All in all, these have gone pretty well. The server has relatively extensive command coverage, it prototypes a whole lot of the IRCv3 proposals and accepted/draft specs, and we pretty regularly update it to match new behaviour written into the Modern spec.

Some of the features that sets Oragono apart from other servers are:

- Extensive IRCv3 support.
- Extensive logging and oper privilege levels configuration.
- Integrated user account and channel registration system (no services required!).
- Native Unicode support (including appropriate casemapping).
- Support for [multiple languages](https://crowdin.com/project/oragono).
- Bouncer-like features, including allowing multiple clients to use the same nickname

Oragono has multiple communities using it as a day-to-day chat server and is fairly mature --- we encourage you to consider it for your community!

## Scalability

We believe Oragono should scale comfortably to 10,000 clients and 2,000 clients per channel, making it suitable for small to medium-sized teams and communities. Oragono does not currently support server-to-server linking (federation), meaning that all clients must connect to the same instance. However, since Oragono is implemented in Go, it is reasonably effective at distributing work across multiple cores on a single server; in other words, it should "scale up" rather than "scaling out".

In the relatively near term, we plan to make Oragono [highly available](https://github.com/oragono/oragono/issues/343), and in the long term, we hope to support [federation](https://github.com/oragono/oragono/issues/26) as well.

If you're interested in deploying Oragono at scale, or want performance tuning advice, come find us on [`#oragono` on freenode](ircs://irc.freenode.net:6697/#oragono), we're very interested in what our software can do!


--------------------------------------------------------------------------------------------


# Installing

In this section, we'll explain how to install and use the Oragono IRC server.


## Windows

To get started with Oragono on Windows:

1. Make sure you have the [latest release](https://github.com/oragono/oragono/releases/latest) downloaded.
1. Extract the zip file to a folder.
1. Copy and rename `oragono.yaml` to `ircd.yaml`.
1. Open up `ircd.yaml` using any text editor, and then save it once you're happy.
1. Open up a `cmd.exe` window, then `cd` to where you have Oragono extracted.
1. Run `oragono.exe mkcerts` if you want to generate new self-signed SSL/TLS certificates (note that you can't enable STS if you use self-signed certs).

To start the server, type `oragono.exe run` and hit enter, and the server should start!


## macOS / Linux / Raspberry Pi

To get started with Oragono on macOS, Linux, or on a Raspberry Pi:

1. Make sure you have the [latest release](https://github.com/oragono/oragono/releases/latest) for your OS/distro downloaded.
1. Extract the tar.gz file to a folder.
1. Copy and rename `oragono.yaml` to `ircd.yaml`.
1. Open up `ircd.yaml` using any text editor, and then save it once you're happy.
1. Open up a Terminal window, then `cd` to where you have Oragono extracted.
1. Run `./oragono mkcerts` if you want to generate new self-signed SSL/TLS certificates (note that you can't enable STS if you use self-signed certs).

To start the server, type `./oragono run` and hit enter, and the server should be ready to use!

If you're using Arch Linux, you can also install the [`oragono` package](https://aur.archlinux.org/packages/oragono/) from the AUR.


## Running oragono as a service on Linux

The recommended way to operate oragono as a service on Linux is via systemd. This provides a standard interface for starting, stopping, and rehashing (via `systemctl reload`) the service. It also captures oragono's loglines (sent to stderr in the default configuration) and writes them to the system journal.

If you're using Arch, the abovementioned AUR package bundles a systemd file for starting and stopping the server. If you're rolling your own deployment, here's an [example](https://github.com/darwin-network/slash/blob/master/etc/systemd/system/ircd.service) of a systemd unit file that can be used to run Oragono as an unprivileged role user.

On a non-systemd system, oragono can be configured to log to a file and used [logrotate(8)](https://linux.die.net/man/8/logrotate), since it will reopen its log files (as well as rehashing the config file) upon receiving a SIGHUP.


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

These are the two ways you can register an account, either one will work:

    /QUOTE ACC REGISTER <username> * passphrase <password>
    /NS REGISTER <password>

This is the way to go if you want to use a regular password. `<username>` and `<password>` are your username and password, respectively; if you go the `/NS REGISTER` route, then your current nickname will become your username. Your password cannot contain spaces, but make sure to use a strong one anyway.

If you want to use a TLS client certificate instead of a password to authenticate (`SASL EXTERNAL`), then you can use the commands below to do so. (If you're not sure what this is, don't worry – just use the above password method to register an account.)

    /QUOTE ACC REGISTER <username> * certfp *
    /NS REGISTER *

Once you've registered, you'll need to setup SASL to login (or use NickServ IDENTIFY). One of the more complete SASL instruction pages is Freenode's page [here](https://freenode.net/kb/answer/sasl). Open up that page, find your IRC client and then setup SASL with your chosen username and password!

## Account/Nick Modes

Oragono supports several different modes of operation with respect to accounts and nicknames.

### Traditional / lenient mode

This is the default mode, and makes Oragono's services act similar to Quakenet's Q bot. In this mode, users cannot own or reserve nicknames. In other words, there is no connection between account names and nicknames. Anyone can use any nickname (as long as it's not already in use by another running client). However, accounts are still useful: they can be used to register channels (see below), and some IRCv3-capable clients (with the `account-tag` or `extended-join` capabilities) may be able to take advantage of them.

To enable this mode, set the following configs (this is the default mode):

* `accounts.registration.enabled = true`
* `accounts.authentication-enabled = true`
* `accounts.nick-reservation.enabled = false`

### Nick ownership

This mode makes Oragono's services act like those of a typical IRC network (like Freenode). In this mode, registering an account gives you privileges over the use of that account as a nickname. The server will then help you to enforce control over your nickname(s):

* You can proactively prevent anyone from using your nickname, unless they're already logged into your account
* Alternately, you can give clients a grace period to log into your account, but if they don't and the grace period expires, the server will change their nickname to something else
* Alternately, you can forego any proactive enforcement – but if you decide you want to reclaim your nickname from a squatter, you can `/msg Nickserv ghost stolen_nickname` and they'll be disconnected
* You can associate additional nicknames with your account by changing to it and then issuing `/msg NickServ group`

To enable this mode, set the following configs:

* `accounts.registration.enabled = true`
* `accounts.authentication-enabled = true`
* `accounts.nick-reservation.enabled = true`

The following additional configs may be of interest:

* `accounts.nick-reservation.method = strict` ; we currently recommend strict nickname enforcement as the default, since we've found that users find it less confusing.
* `accounts.nick-reservation.allow-custom-enforcement = true` ; this allows people to opt into timeout-based enforcement or opt out of enforcement as they wish. For details on how to do this, `/msg NickServ help set`.

### SASL-only mode

This mode is comparable to Slack, Mattermost, or similar products intended as internal chat servers for an organization or team. In this mode, clients cannot connect to the server unless they log in with SASL as part of the initial handshake. This allows Oragono to be deployed facing the public Internet, with fine-grained control over who can log in.

In this mode, clients must have a valid account to connect, so they cannot register their own accounts. Accordingly, an operator must do the initial account creation, using the `SAREGISTER` command of NickServ. (For more details, `/msg NickServ help saregister`.) To bootstrap this process, you can make an initial connection from localhost, which is exempt (by default) from the requirement, or temporarily add your own IP to the exemption list. You can also use a more permissive configuration for bootstrapping, then switch to this one once you have your account. Another possibility is permanently exempting an internal network, e.g., `10.0.0.0/8`, that only trusted people can access.

To enable this mode, set the following configs:

* `accounts.registration.enabled = false`
* `accounts.authentication-enabled = true`
* `accounts.require-sasl.enabled = true`
* `accounts.nick-reservation.enabled = true`

Additionally, the following config is recommended:

* `accounts.nick-reservation.method = strict`


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


## Bouncer

Traditionally, every connection to an IRC server is separate must use a different nickname. [Bouncers](https://en.wikipedia.org/wiki/BNC_%28software%29#IRC) are used to work around this, by letting multiple clients connect to a single nickname. With Oragono, if the server is configured to allow it, multiple clients can share a single nickname without needing a bouncer. To use this feature, both connections must authenticate with SASL to the same user account and then use the same nickname during connection registration (while connecting to the server) – once you've logged-in, you can't share another nickname.

To enable this functionality, set `accounts.bouncer.enabled` to `true`. Setting `accounts.bouncer.allowed-by-default` to `true` will allow this for everyone – by default, users need to opt-in to shared connections using `/msg NickServ SET BOUNCER`.

You can see a list of your active sessions and their idle times with `/msg NickServ sessions` (network operators can use `/msg NickServ sessions nickname` to see another user's sessions).


## History

Oragono can store a limited amount of message history in memory and replay it, which is useful for covering brief disconnections from IRC. You can access this using the `/HISTORY` command (depending on your client, you may need to use `/QUOTE history` instead), for example `/HISTORY #mychannel 100` to get the 100 latest messages from `#mychannel`.

Server administrators can configure `history.autoreplay-on-join` to automatically send clients a fixed number of history lines when they join a channel. Users can use `/msg NickServ set autoreplay-lines` to opt in or out of this behavior.

We are working on a number of improvements to this functionality:

* We currently emulate the ZNC playback module for clients that have special ZNC support (see the "ZNC" section below)
* The [`/CHATHISTORY`](https://github.com/ircv3/ircv3-specifications/pull/349) command will be a standardized way for clients to request history lines
* [Connection resuming](https://github.com/ircv3/ircv3-specifications/pull/306), which we support in draft form, automatically replays history lines to clients who return after a brief disconnection


## IP cloaking

Unlike many other chat and web platforms, IRC traditionally exposes the user's IP and hostname information to other users. This is in part because channel owners and operators (who have privileges over a single channel, but not over the server as a whole) need to be able to ban spammers and abusers from their channels, including via hostnames in cases where the abuser tries to evade the ban.

IP cloaking is a way of balancing these concerns about abuse with concerns about user privacy. With cloaking, the user's IP address is deterministically "scrambled", typically via a cryptographic [MAC](https://en.wikipedia.org/wiki/Message_authentication_code), to form a "cloaked" hostname that replaces the usual reverse-DNS-based hostname. Users cannot reverse the scrambling to learn each other's IPs, but can ban a scrambled address the same way they would ban a regular hostname.

Oragono supports cloaking, which can be enabled via the `server.ip-cloaking` section of the config. However, Oragono's cloaking behavior differs from other IRC software. Rather than scrambling each of the 4 bytes of the IPv4 address (or each 2-byte pair of the 8 such pairs of the IPv6 address) separately, the server administrator configures a CIDR length (essentially, a fixed number of most-significant-bits of the address). The CIDR (i.e., only the most significant portion of the address) is then scrambled atomically to produce the cloaked hostname. This errs on the side of user privacy, since knowing the cloaked hostname for one CIDR tells you nothing about the cloaked hostnames of other CIDRs --- the scheme reveals only whether two users are coming from the same CIDR. We suggest using 32-bit CIDRs for IPv4 (i.e., the whole address) and 64-bit CIDRs for IPv6, since these are the typical assignments made by ISPs to individual customers.

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

More complete support for account-based private channels is [planned](https://github.com/oragono/oragono/issues/69). In the meantime, here's a workaround:

1. Register your channel (`/msg ChanServ register #example`)
1. Set it to be invite-only (`/mode #example +i`)
1. Grant persistent half-operator status to the desired account names (`/msg ChanServ amode #example +h alice`)

Anyone with persistent half-operator privileges or higher will be able to join without an invite.

-------------------------------------------------------------------------------------------


# IRC over TLS

IRC has traditionally been available over both plaintext (on port 6667) and SSL/TLS (on port 6697). We recommend that you make your server available exclusively via TLS, since exposing plaintext access allows for unauthorized interception or modification of user data or passwords. While the default config file exposes a plaintext public port, it also contains instructions on how to disable it or replace it with a 'dummy' plaintext listener that simply directs users to reconnect using TLS.


## How do I use Let's Encrypt certificates?

[Let's Encrypt](https://letsencrypt.org) is a widely recognized certificate authority that provides free certificates. Here's a quick-start guide for using those certificates with Oragono:

1. Follow this [guidance](https://letsencrypt.org/getting-started/) from Let's Encrypt to create your certificates.
2. You should now have a set of `pem` files, Mainly, we're interested in your `live/` Let's Encrypt directory (e.g. `/etc/letsencrypt/live/<site>/`).
3. Here are how the config file keys map to LE files:
    - `cert: tls.crt` is `live/<site>/fullchain.pem`
    - ` key: tls.key` is `live/<site>/privkey.pem`
4. You may need to copy the `pem` files to another directory so Oragono can read them, or similarly use a script like [this one](https://github.com/darwin-network/slash/blob/master/etc/bin/install-lecerts) to automagically do something similar.
5. By default, `certbot` will automatically renew your certificates. Oragono will only reread certificates when it is restarted, or during a rehash (e.g., on receiving the `/rehash` command or the `SIGHUP` signal). You can add an executable script to `/etc/letsencrypt/renewal-hooks/post` that can perform the rehash. Here's one example of such a script:

```bash
#!/bin/bash
pkill -HUP oragono
```

The main issues you'll run into are going to be permissions issues. This is because by default, certbot will generate certificates that non-root users can't (and probably shouldn't) read. If you run into trouble, look over the script in step **4** and/or make sure you're copying the files to somewhere else, as well as giving them correct permissions with `chown`, `chgrp` and `chmod`.

On other platforms or with alternative ACME tools, you may need to use other steps or the specific files may be named differently.


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
                key: tls.key
                cert: tls.crt

    sts:
        enabled: true

        # how long clients should be forced to use TLS for.
        duration: 1mo2d5m
```


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

### +s - Server Notice Masks

This is a special 'list mode'. If you're an IRC operator, this mode lets you see special server notices that get sent out. See the Server Notice Masks section for more information on this mode.

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
        - "oper:local_kill"
        - "oper:local_ban"
        - "oper:local_unban"
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


--------------------------------------------------------------------------------------------


# Acknowledgements

Always, thanks to Jeremy Latt for creating Ergonomadic. Thanks for Edmund Huber for maintaining Ergonomadic and providing useful help while transitioning.

Thanks to Euan Kemp (euank) for the contributions and help with this, along with other projects, and to James Mills, Vegax and Sean Enck for various other help and contributions on the server.

And a massive thanks to Shivaram Lingamneni (slingamn) for being an amazing co-maintainer of Oragono! You've contributed a lot to Oragono, and really convinced me to step up with this and take the server forward in a big way. I'm grateful for everything you've done, and working with ya' is a pleasure.
