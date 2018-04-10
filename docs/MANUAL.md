
          ▄▄▄   ▄▄▄·  ▄▄ •        ▐ ▄       
    ▪     ▀▄ █·▐█ ▀█ ▐█ ▀ ▪▪     •█▌▐█▪     
     ▄█▀▄ ▐▀▀▄ ▄█▀▀█ ▄█ ▀█▄ ▄█▀▄▪▐█▐▐▌ ▄█▀▄ 
    ▐█▌.▐▌▐█•█▌▐█ ▪▐▌▐█▄▪▐█▐█▌ ▐▌██▐█▌▐█▌.▐▌
     ▀█▄▀▪.▀  ▀ ▀  ▀ ·▀▀▀▀  ▀█▄▀ ▀▀ █▪ ▀█▄▀▪

         Oragono IRCd Manual 2018-04-01
              https://oragono.io/

_Copyright © 2018 Daniel Oaks <daniel@danieloaks.net>_


--------------------------------------------------------------------------------------------


# Table of Contents

- Introduction
    - Project Basics
- Installing
    - Windows
    - macOS / Linux / Raspberry Pi
- Features
    - User Accounts
    - Channel Registration
    - Language
- Frequently Asked Questions
- Modes
    - User Modes
    - Channel Modes
    - Channel Prefixes
- Commands
- Acknowledgements


--------------------------------------------------------------------------------------------


# Introduction

This document goes over the Oragono IRC server, how to get it running and how to use it once it is up and running!

If you have any suggestions, issues or questions, feel free to submit an issue on our [GitHub repo](https://github.com/oragono/oragono/) or ask in our channel [`#oragono` on Freenode](ircs://irc.freenode.net:6697/#oragono).


## Project Basics

Let's go over some basics, for those new to Oragono. My name's Daniel, and I started the project (it was forked off a server called [Ergonomadic](https://github.com/edmund-huber/ergonomadic) that'd been around for a few years). In addition to Oragono, I also do a lot of IRC specification work with the [various](https://modern.ircdocs.horse) [ircdocs](https://defs.ircdocs.horse) [projects](https://ircdocs.horse/specs/) and with the [IRCv3 WG](https://ircv3.net/).

Oragono's a new IRC server, written from scratch. My main goals when starting the project was to write a server that:

- Is fully-functional (most of my attempts in the past which had been 'toy' quality).
- I could easily prototype new [IRCv3](https://ircv3.net/) proposals and features in.
- I could consider a reference implementation for the [Modern spec](https://modern.ircdocs.horse).

All in all, these have gone pretty well. The server has relatively extensive command coverage, it prototypes a whole lot of the IRCv3 proposals and accepted/draft specs, and I pretty regularly update it to match new behaviour written into the Modern spec.

Some of the features that sets Oragono apart from other servers are:

- Extensive IRCv3 support (more than any other server, currently).
- Extensive logging and oper privilege levels.
- Integrated user account and channel registration system (no services required!).
- Native Unicode support (including casemapping for that Unicode).
- Support for [multiple languages](https://crowdin.com/project/oragono).


--------------------------------------------------------------------------------------------


# Installing

In this section, we'll explain how to install and use the Oragono IRC server.


## Windows

To get started with Oragono on Windows:

1. Make sure you have the [latest release](https://github.com/oragono/oragono/releases/latest) downloaded.
2. Extract the zip file to a folder.
3. Copy and rename `oragono.yaml` to `ircd.yaml`.
4. Open up `ircd.yaml` using any text editor, and then save it once you're happy.
5. Open up a `cmd.exe` window, then `cd` to where you have Oragono extracted.
6. Run `oragono.exe initdb` (this creates the database).
7. Run `oragono.exe mkcerts` if you want to generate new self-signed SSL/TLS certificates (note that you can't enable STS if you use self-signed certs).

To start the server, type `oragono.exe run` and hit enter, and the server should start!


## macOS / Linux / Raspberry Pi

To get started with Oragono on macOS, Linux, or on a Raspberry Pi:

1. Make sure you have the [latest release](https://github.com/oragono/oragono/releases/latest) for your OS/distro downloaded.
2. Extract the tar.gz file to a folder.
3. Copy and rename `oragono.yaml` to `ircd.yaml`.
4. Open up `ircd.yaml` using any text editor, and then save it once you're happy.
5. Open up a Terminal window, then `cd` to where you have Oragono extracted.
6. Run `./oragono initdb` (this creates the database).
7. Run `./oragono mkcerts` if you want to generate new self-signed SSL/TLS certificates (note that you can't enable STS if you use self-signed certs).

To start the server, type `./oragono run` and hit enter, and the server should be ready to use!

If you're using Arch Linux, you can also install the [`oragono` package](https://aur.archlinux.org/packages/oragono/) from the AUR. This lets you bypass the above process and bundles a systemd service file for easily starting the server.


--------------------------------------------------------------------------------------------


# Features

In this section, we'll explain and go through using various features of the Oragono IRC server.


## User Accounts

In most IRC servers you can use `NickServ` to register an account. You can do the same thing with Oragono, by default, with no other software needed!

However, there are some differences between how Oragono handles accounts and how most other servers do. Some of these differences are that:

- In Oragono, account names are completely unrelated to nicknames.
- In Oragono, there's no nickname ownership unless you configure a config section.

With nickname ownership and account names, on most IRC servers your nickname and your account name are one and the same thing. This isn't the case with Oragono. When using Oragono, your nickname and account name are totally unrelated. However, you can enable nickname ownership with the `nick-reservation` section in the config.

These are the two ways you can register an account:

    /QUOTE ACC REGISTER <username> * passphrase :<password>
    /NS REGISTER <username> <password>

This is the way to go if you want to use a regular password. `<username>` and `<password>` are your username and password, respectively (make sure the leave that one `:` before your actual password!).

    /QUOTE ACC REGISTER <username> * certfp *
    /NS REGISTER <username>

If you want to use a TLS client certificate to authenticate (`SASL CERTFP`), then you can use the above method to do so. If you're not sure what this is, don't worry – just use the above password method to register an account.

Once you've registered, you'll need to setup SASL to login (or use NickServ IDENTIFY). One of the more complete SASL instruction pages is Freenode's page [here](https://freenode.net/kb/answer/sasl). Open up that page, find your IRC client and then setup SASL with your chosen username and password!


## Channel Registration

Once you've registered an account, you can also register channels. If you own a channel, you'l be opped whenever you join it, and the topic/modes will be remembered and re-applied whenever anyone rejoins the channel.

To register a channel, make sure you're joined to it and logged into your account. If both those are true, you can send this command to register your account:

    /CS REGISTER #channelname

For example, `/CS REGISTER #channel` will register the channel `#test` to my account. If you have a registered channel, you can use `/CS OP #channel` to regain ops in it. Right now, the options for a registered channel are pretty sparse, but we'll add more as we go along.


## Language

Oragono supports multiple languages! Specifically, once you connect you're able to get server messages in other languages (messages from other users will still be in their original languages, though).

To see which languages are supported, run this command:

    /QUOTE CAP LS 302

In the resulting text, you should see a token that looks something like this:

    draft/languages=5,en,~fr-FR,no,~pt-BR,tr-TR

That's the list of languages we support. For the token above, the supported languages are:

- `en`: English
- `fr-FR`: French (incomplete)
- `no`: Norwegian
- `pt-BR`: Brazilian Portugese (incomplete)
- `tr-TR`: Turkish

To change to a specific language, you can use the `LANGUAGE` command like this:

    /LANGUAGE tr-TR

The above will change the server language to Turkish. Substitute any of the other language codes in to select other languages, and run `/LANGUAGE en` to get back to standard English.

Our language and translation functionality is very early, so feel free to let us know if there are any troubles with it! If you know another language and you'd like to contribute, we've got a CrowdIn project here: [https://crowdin.com/project/oragono](https://crowdin.com/project/oragono)


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


--------------------------------------------------------------------------------------------


# Modes

On IRC, you can set modes on users and on channels. Modes are basically extra information that changes how users and channels work.

In this section, we give an overview of the modes Oragono supports.


## User Modes

These are the modes which can be set on you when you're connected.

### +a - Away

If this mode is set, you're marked as 'away'. To set and unset this mode, you use the `/AWAY` command.

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

If this mode is set, it means that your channel should be marked as 'secret'. Your channel won't show up in `/LIST` or `/WHOIS`.

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


# Acknowledgements

Always, thanks to Jeremy Latt for creating Ergonomadic. Thanks for Edmund Huber for maintaining Ergonomadic and providing useful help while transitioning.

Thanks to Euan Kemp (euank) for the contributions and help with this, along with other projects, and to James Mills, Vegax and Sean Enck for various other help and contributions on the server.

And a massive thanks to Shivaram Lingamneni (slingamn) for being an awesome co-maintainer of Oragono! You really convinced me to step up with this and take it forward in a big way, and I'm grateful for that.
