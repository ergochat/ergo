         __ __  ______ ___  ______ ___ 
      __/ // /_/ ____/ __ \/ ____/ __ \
     /_  // __/ __/ / /_/ / / __/ / / /
    /_  // __/ /___/ _, _/ /_/ / /_/ / 
     /_//_/ /_____/_/ |_|\____/\____/  

           Ergo IRCd User Guide
            https://ergo.chat/

_Copyright © Daniel Oaks <daniel@danieloaks.net>, Shivaram Lingamneni <slingamn@cs.stanford.edu>_


--------------------------------------------------------------------------------------------


 Table of Contents

- [Introduction](#introduction)
- [About IRC](#about-irc)
- [How Ergo is different](#how-ergo-is-different)
- [Account registration](#account-registration)
- [Channel registration](#channel-registration)
- [Always-on](#always-on)
- [Multiclient](#multiclient)
- [History](#history)

--------------------------------------------------------------------------------------------


# Introduction

Welcome to Ergo, a modern IRC server!

This guide is for end users of Ergo (people using Ergo to chat). If you're installing your own Ergo instance, you should consult the official manual instead (a copy should be bundled with your release, in the `docs/` directory).

This guide assumes that Ergo is in its default or recommended configuration; Ergo server administrators can change settings to make the server behave differently. If something isn't working as expected, ask your server administrator for help.

# About IRC

Before continuing, you should be familiar with basic features of the IRC platform. If you're comfortable with IRC, you can skip this section.

[IRC](https://en.wikipedia.org/wiki/Internet_Relay_Chat) is a chat platform invented in 1988, which makes it older than the World Wide Web! At its most basic level, IRC is a chat system composed of chat rooms; these are called "channels" and their names begin with a `#` character (this is actually the origin of the [hashtag](https://www.cmu.edu/homepage/computing/2014/summer/originstory.shtml)!). As a user, you "join" the channels you're interested in, enabling you to participate in those discussions.

Here are some guides covering the basics of IRC:

* [Fedora Magazine: Beginner's Guide to IRC](https://fedoramagazine.org/beginners-guide-irc/)
* [IRCHelp's IRC Tutorial](https://www.irchelp.org/faq/irctutorial.html) (in particular, section 3, "Beyond the Basics")

# How Ergo is different

Ergo differs in many ways from conventional IRC servers. If you're *not* familiar with other IRC servers, you may want to skip this section. Here are some of the most salient differences:

* Ergo integrates a "bouncer" into the server. In particular:
    * Ergo stores message history for later retrieval.
    * You can be "present" on the server (joined to channels, able to receive DMs) without having an active client connection to the server.
    * Conversely, you can use multiple clients to view / control the same presence (nickname) on the server, as long as you authenticate with SASL when connecting.
* Ergo integrates "services" into the server.  In particular:
    * Nicknames are strictly reserved: once you've registered your nickname, you must log in in order to use it. Consequently, SASL is more important when using Ergo than in other systems.
    * All properties of registered channels are protected without the need for `ChanServ` to be joined to the channel.
* Ergo "cloaks", i.e., cryptographically scrambles, end user IPs so that they are not displayed publicly.
* By default, the user/ident field is inoperative in Ergo: it is always set to `~u`, regardless of the `USER` command or the client's support for identd. This is because it is not in general a reliable or trustworthy way to distinguish users coming from the same IP. Ergo's integrated bouncer features should reduce the need for shared shell hosts and hosted bouncers (one of the main remaining use cases for identd).
* By default, Ergo is only accessible via TLS.

# Account registration

Although (as in other IRC systems) basic chat functionality is available without creating an account, most of Ergo's features require an account. You can create an account by sending a direct message to `NickServ`. (In IRC jargon, `NickServ` is a "network service", but if you're not familiar with the concept you can just think of it as a bot or a text user interface.) In a typical client, this will be:

```
/msg NickServ register mySecretPassword validEmailAddress@example.com
```

This registers your current nickname as your account name, with the password `mySecretPassword` (replace this with your own secret password!)

Once you have registered your account, you must configure SASL in your client, so that you will be logged in automatically on each connection. [libera.chat's SASL guide](https://libera.chat/guides/sasl) covers most popular clients.

If your client doesn't support SASL, you can typically use the "server password" (`PASS`) field in your client to log into your account automatically when connecting. Set the server password to `accountname:accountpassword`, where `accountname` is your account name and `accountpassword` is your account password.

For information on how to use a client certificate for authentication, see the [operator manual](https://github.com/ergochat/ergo/blob/stable/docs/MANUAL.md#client-certificates).

# Channel registration

Once you've registered your nickname, you can use it to register channels. By default, channels are ephemeral; they go away when there are no longer any users in the channel, or when the server is restarted. Registering a channel gives you permanent control over it, and ensures that its settings will persist. To register a channel, send a message to `ChanServ`:

```
/msg ChanServ register #myChannel
```

You must already be an operator (have the `+o` channel mode --- your client may display this as an `@` next to your nickname). If you're not a channel operator in the channel you want to register, ask your server administrator for help.

# Always-on

By default, if you lose your connection to the IRC server, you are no longer present on the server; other users will see that you have "quit", you will no longer appear in channel lists, and you will not be able to receive direct messages. Ergo supports "always-on clients", where you remain on the server even when you are disconnected. To enable this, you can send a message to `NickServ`:

```
/msg NickServ set always-on true
```

# Multiclient

Ergo natively supports attaching multiple clients to the same nickname (this normally requires the use of an external bouncer, like ZNC or WeeChat's "relay" functionality). To use this feature, simply authenticate with SASL (or the PASS workaround, if necessary) when connecting. In the recommended configuration of Ergo, you will receive the nickname associated with your account, even if you have other clients already using it.

# History

Ergo stores message history on the server side (typically not an unlimited amount --- consult your server's FAQ, or your server administrator, to find out how much is being stored and how long it's being retained).

1. The [IRCv3 chathistory specification](https://ircv3.net/specs/extensions/chathistory) offers the most fine-grained control over history replay. It is supported by [Gamja](https://git.sr.ht/~emersion/gamja), [Goguma](https://sr.ht/~emersion/goguma/), and [Kiwi IRC](https://github.com/kiwiirc/kiwiirc), and hopefully other clients soon.
1. We emulate the [ZNC playback module](https://wiki.znc.in/Playback) for clients that support it. You may need to enable support for it explicitly in your client. For example, in [Textual](https://www.codeux.com/textual/), go to "Server properties", select "Vendor specific", uncheck "Do not automatically join channels on connect", and check "Only play back messages you missed". ZNC's wiki page covers other common clients (although if the feature is only supported via a script or third-party extension, the following option may be easier).
1. If you set your client to always-on (see the previous section for details), you can set a "device ID" for each device you use. Ergo will then remember the last time your device was present on the server, and each time you sign on, it will attempt to replay exactly those messages you missed. There are a few ways to set your device ID when connecting:
    - You can add it to your SASL username with an `@`, e.g., if your SASL username is `alice` you can send `alice@phone`
    - You can add it in a similar way to your IRC protocol username ("ident"), e.g., `alice@phone`
    - If login to user accounts via the `PASS` command is enabled on the server, you can provide it there, e.g., by sending `alice@phone:hunter2` as the server password
1. If you only have one device, you can set your client to be always-on and furthermore `/msg NickServ set autoreplay-missed true`. This will replay missed messages, with the caveat that you must be connecting with at most one client at a time.
1. You can manually request history using `/history #channel 1h` (the parameter is either a message count or a time duration). (Depending on your client, you may need to use `/QUOTE history` instead.)
1. You can autoreplay a fixed number of lines (e.g., 25) each time you join a channel using `/msg NickServ set autoreplay-lines 25`.

# Private channels

If you have registered a channel, you can make it private. The best way to do this is with the `+i` ("invite-only") mode:

1. Set your channel to be invite-only (`/mode #example +i`)
1. Identify the users you want to be able to access the channel. Ensure that they have registered their accounts (you should be able to see their registration status if you `/WHOIS` their nicknames).
1. Add the desired nick/account names to the invite exception list (`/mode #example +I alice`)
1. If you want to grant a persistent channel privilege to a user, you can do it with `CS AMODE` (`/msg ChanServ AMODE #example +o bob`)
