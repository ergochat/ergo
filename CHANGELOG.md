# Changelog
All notable changes to Oragono will be documented in this file.

## [1.1.1] - 2019-07-21
Oragono 1.1.1 is a bugfix release for flaws in message handling, including one with security implications.

Many thanks to [@streaps](https://github.com/streaps) for reporting issues.

### Upgrade notes

This release does not change the database or configuration file format.

### Security
* Previous releases of Oragono would incorrectly relay chat messages containing the `\r` byte. An attacker could use this to spoof protocol messages from the server (depending on the implementation of the victim's client). This has been fixed. (#610)

### Fixed
* Fixed incorrect rejection of messages with multiple spaces (#602, thanks [@streaps](https://github.com/streaps)!)

## [1.1.0] - 2019-06-27
We're pleased to announce Oragono version 1.1.0. This version has a number of exciting improvements, including:

* Simplified commands for registering new accounts with NickServ.
* Support for IP cloaking.
* Support for attaching multiple clients to the same nickname.
* Support for the newly ratified [message tags](https://ircv3.net/specs/extensions/message-tags.html) and [message ID](https://ircv3.net/specs/extensions/message-ids.html) IRCv3 specifications; client developers are invited to use Oragono as a reference when implementing these specifications.
* Support for running Oragono as a Tor hidden service.

Many thanks to [@Ascrod](https://github.com/Ascrod), [@amyspark](https://github.com/amyspark), [@bogdomania](https://github.com/bogdomania), [@csmith](https://github.com/csmith), [@jesopo](https://github.com/jesopo), [@jwheare](https://github.com/jwheare), lover, and [@transitracer](https://github.com/oragono/oragono/issues/456) for reporting issues and contributing patches, and also to [@bogdomania](https://github.com/bogdomania), Elvedin Hušić, Nuve, and [@streaps](https://github.com/streaps) for contributing translations.

### Upgrade notes

This release includes a database change. If you have `datastore.autoupgrade` set to `true` in your configuration, it will be automatically applied when you restart Oragono. Otherwise, you can update the database manually by running `oragono upgradedb` (see the manual for complete instructions).

No changes to your configuration file should be required for this upgrade. However, updating the file is necessary to enable some new functionality, as described below.

### Config changes
* `tor-listeners` section added for configuring listeners for use with Tor.
* `compatibility` section added for toggling compatibility behaviors for legacy clients.
* `ip-cloaking` section added for configuring cloaking.
* `bouncer` section added for configuring bouncer-like features (in particular, whether multiple clients can use the same nickname).
* `check-ident` now has recommended value `false`.
* `nick-reservation.method` now has recommended value "strict"`.
* `fakelag.enabled` now has recommended value `true`.
* `limits.linelen.tags` removed due to ratification of the [message-tags spec](https://ircv3.net/specs/extensions/message-tags.html), which fixes the maximum tags length at 8191 bytes.
* `limits.registration-messages` added to restrict how many messages a user can send to the server during connection registration (while connecting to the server).
* `channels.operator-only-creation` added to optionally restrict creation of new channels to ircops (#537).

### Security
* Users can no longer impersonate network services like ChanServ by using confusing nicks like "ChɑnServ" (#519, thanks [@csmith](https://github.com/csmith)!).
* Closed several loopholes in confusable nick detection (#562, #564, #570, thanks lover!)
* Secret channels (mode `+s`) now act more secret (#380, thanks [@csmith](https://github.com/csmith)!).
* The `+R` (registered-only) mode now prevents unregistered users from joining the channel, not just from speaking (#463, thanks [@bogdomania](https://github.com/bogdomania)!).
* Limited how many messages clients can send during connection registration to mitigate potential DoS attacks (#505).
* Attempting to reauthenticate with SASL now fails with `907 ERR_SASLALREADY` (#476).

### Fixed
* Fixed `/ISON` command reporting users as always being online (#479).
* Fixed clients who negotiated CAP version 302 or higher not receiving cap-notify messages (#464).
* We now treat channel privileges such as halfop more consistently (#400).
* Fixed a bug where clients could receive message tags they hadn't enabled (#434).
* When replaying history, messages now have more consistent IDs and timestamps
* IDs and timestamps are now applied more consistently to messages (#388, #477, #483).
* Client-to-client tags are now stored and replayed in message history (#437).
* Fixed various error numerics that were being sent with incorrect parameters (#425, thanks [@Ascrod](https://github.com/Ascrod)!).
* Fixed STATUSMSG not adding the correct prefix to the channel when relaying the message (#467).
* Fixed `/RENAME` command not correctly renaming the channel for some users (#300, thanks [@jesopo](https://github.com/jesopo)!).
* History playback is now batched when applicable (#456, thanks [@transitracer](https://github.com/oragono/oragono/issues/456)!).
* Notices from NickServ/ChanServ/etc should display better in some clients (#496, thanks [@jwheare](https://github.com/jwheare)!).
* Fixed nickname timer warnings not displaying correctly sometimes (#449, thanks [@bogdomania](https://github.com/bogdomania)!).
* When history playback is disabled, the `/HISTORY` command now says so instead of silently failing (#429, thanks [@bogdomania](https://github.com/bogdomania)!).
* The `/HOSTSERV ON/OFF` commands now tell you when you don't have a vhost (#404, thanks [@bogdomania](https://github.com/bogdomania)!).
* When operators use the `/SANICK` command, the snomask now says which operator did it instead of saying the target changed their nickname themselves (#360, thanks [@bogdomania](https://github.com/bogdomania)!).
* History playback now includes messages that the user sent themselves (especially useful with the new bouncer-like capabilities) (#487).

### Added
* IP cloaking is now supported (see the manual for details) (#108).
* Users can now attach multiple clients to the same nickname (see the manual for details) (#403).
* Oragono can now be used as a Tor hidden service (see the manual for details) (#369).
* The `znc.in/playback` capability is now supported, which can automate history playback for clients that support it (#486).
* User preference system controlling various behaviors (`/msg NickServ help set` for details) (#466).
* Support for the [draft/event-playback](https://github.com/DanielOaks/ircv3-specifications/blob/master+event-playback/extensions/batch/history.md) spec (#457).
* The `TAGMSG` and `NICK` messages are now replayable in history (#457).
* Added the draft IRCv3 [`SETNAME` command](https://ircv3.net/specs/extensions/setname) for changing your realname (#372).
* Added new Bosnian (bs-BA) translation (thanks to Elvedin Hušić!).
* Added new German (de-DE) translation (thanks to streaps!).

### Changed
* Registering an account with NickServ is now `/msg NickServ register <password>`, which registers the current nickname as an account, matching other services (#410).
* Added a compatibility hack to make SASL work with ZNC 1.6.x (#261).
* We now support the ratified [message-tags](https://ircv3.net/specs/extensions/message-tags.html) spec, replacing `draft/message-tags-0.2`.
* We now support the ratified [message IDs](https://ircv3.net/specs/extensions/message-ids.html) spec, replacing `draft/msgid`.
* The [`oragono.io/maxline-2`](https://oragono.io/maxline-2) capability has replaced `oragono.io/maxline`, the new version now working alongside the ratified message-tags spec (#433).
* We now support [`draft/resume-0.5`](https://github.com/ircv3/ircv3-specifications/pull/306) and the associated `BRB` command, replacing `draft/resume-0.3`.
* Upgraded support for the `/RENAME` command to the [latest draft of the specification](https://github.com/ircv3/ircv3-specifications/pull/308).
* Upgraded support for the `/ACC` command to the [latest draft of the specification](https://github.com/DanielOaks/ircv3-specifications/blob/register-and-verify/extensions/acc-core.md) (#453, #455).
* Removed the `+a` away mode as no other servers use it (#468, thanks [@jesopo](https://github.com/jesopo) and [@jwheare](https://github.com/jwheare)!).
* Forcing trailing parameters for legacy compatibility can now be disabled in config (#479).
* `autoreplay-on-join` no longer replays `JOIN` and `PART` lines by default (#474, thanks [@amyspark](https://github.com/amyspark)!).
* snomasks are no longer sent for unregistered clients (#362, thanks [@bogdomania](https://github.com/bogdomania)!).
* `WHOIS` responses no longer include the `690 RPL_WHOISLANGUAGE` numeric, as it doesn't show anything useful to other users (#516).
* `ISON` now reports services (ChanServ/NickServ/etc) as online (#488).
* All times are now reported in UTC (#480).
* `NICKSERV ENFORCE` is deprecated in favor of the new `NICKSERV SET ENFORCE` (the old syntax is still available as an alias).
* The `WHO` command is now treated like `PONG` in that it doesn't count as user activity, since client software often uses it automatically (#485).
* The `NAMES` command now only returns results for the first given channel (#534).
* Updated French (fr-FR) translation (thanks to Nuve!).
* Updated Română (ro-RO) translation (thanks to [@bogdomania](https://github.com/bogdomania)!).

### Internal Notes
* Building Oragono is now easier (#409).
* Official builds now use Go 1.12 (#406).
* Our message building and parsing code is slightly faster now (#387).
* Added the [`oragono.io/nope`](https://oragono.io/nope) capability to encourage clients to request capabilities safely (#511).
* Made some previously untranslatable strings translatable (#407).
* Fixed portability issues with 32-bit architectures (#527).


## [1.0.0] - 2019-02-24
We've finally made it to v1.0.0! With this release, our list of need-to-haves is rounded out, and we reckon the software's ready for production use in smaller networks. slingamn and I have been working with our contributors and translators to prepare a cracker of a release. Thanks to [@csmith](https://github.com/csmith) our [Docker builds](https://hub.docker.com/r/oragono/oragono/) have been updated, with automatic rebuilds as we develop the software. Thanks to [@bogdomania](https://github.com/bogdomania) our translation workflow has been improved a lot.

Highlights include:

* Optional support for storing and replaying message history with the [`draft/resume-0.3` capability](https://github.com/ircv3/ircv3-specifications/pull/306), the draft IRCv3 `CHATHISTORY` command, and a custom `HISTORY` command.
* Better detection of confusing nick/account/channel names.
* User-customizable nickname protection methods.
* An account-only mode in which all clients must have an account and login to it (using SASL) before they can join the server.

Thanks to Mauropek, [@modinfo](https://github.com/modinfo), [@bogdomania](https://github.com/bogdomania), [@Shillos](https://github.com/Shillos), Tony Chen, and Remini for adding new translations. Thanks to [@Ascrod](https://github.com/Ascrod), [@bogdomania](https://github.com/bogdomania), [@csmith](https://github.com/csmith), [@jesopo](https://github.com/jesopo), [@jwheare](https://github.com/jwheare), [@remini1998](https://github.com/remini1998), [@enckse](https://github.com/enckse), and [@iNecas](https://github.com/iNecas) for finding bugs and/or writing new features.

### Config Changes
* `allow-custom-enforcement` key added under `accounts`.
* `allow-plaintext-resume` key added under `server`.
* `history` section added.
* `identlen` key added under `limits`.
* `login-throttling` section added under `accounts`.
* `max-channels-per-account` key added under `channels.registration` (limiting the number of channels that can be registered).
* `max-channels-per-client` key added under `channels` (limiting the number of channels that can be joined).
* `method` key now under `accounts` now allows the value `"optional"`.
* Exemption lists now accept `localhost` as a value, meaning any loopback IPV4, loopback IPV6, or unix domain address.
* Logging type `server` has been added, replacing the `startup`, `rehash`, and `shutdown` types.
* The default logging configuration now logs to stderr only, rather than to both stderr and a file.
* We no longer listen on port `6668` by default (this fixes Docker installs).

### Security
* Added a SASL-only mode in which all clients must authenticate with SASL.
* Added login throttling as a hardening measure against password guessing.
* Configurable limits are imposed on how many channels clients can join or register.

### Added
* Added automagic datastore creation on `oragono run`.
* Added detection and prevention of confusing nicknames, account names, and channel names.
* Added limited message history for connection resuming (to be extended in future).
* Added new Español (es) translation (thanks to Mauropek!).
* Added new Polski (pl) translation (thanks to [@modinfo](https://github.com/modinfo)!).
* Added new Română (ro) translation (thanks to [@bogdomania](https://github.com/bogdomania)!).
* Added new Ελληνικά (el) translation (thanks to [@Shillos](https://github.com/Shillos)!).
* Added new 简体中文 (zh-CN) translation (thanks to Tony Chen and Remini!)).
* Added proposed IRCv3 capability [`draft/setname`](https://github.com/ircv3/ircv3-specifications/pull/361).
* Added subcommands to `NICKSERV`, including:
    * `PASSWD` to change account passwords.
    * `ENFORCE` to set a specific enforcement mechanism on your nick.
    * `SAREGISTER` to allow operators to manually create new user accounts.

### Changed
* `SASL PLAIN` logins now log more correctly.
* Database upgrade failures now provide information about the error that occurred.
* Halfops can now kick unprivileged users.
* Idents (sometimes called "usernames") are now restricted to ASCII, similar to other servers.
* Improved compatibility with ZNC's nickserv module.
* In addition to the founder, now auto-ops (halfop and higher) automatically bypass channel join restrictions.
* Log lines now display time down to milliseconds, instead of just seconds.
* Updated all translation files (thanks to our amazing translators!).
* Updated proposed IRCv3 capability `draft/resume` to [`draft/resume-0.3`](https://github.com/ircv3/ircv3-specifications/pull/306).
* When nick ownership is enabled, users can now select which enforcement mechanism to use with their nickname.

### Fixed
* `INVITE`: Fixed bug where invited users could not join the channel they were invited to (thanks to [@unendingpattern](https://github.com/unendingpattern)!).
* [`oragono.io/maxline`](https://oragono.io/maxline) capability was accidentally disabled, and is now re-enabled.
* `oragono genpasswd` now works when piping input in (fixes Docker installs).
* `PRIVMSG`: Messages sent to multiple clients (such as channel messages) now share the same timestamp (previously each client got a very slightly different time).
* `WHOIS`: Now responds properly for NickServ, ChanServ, etc.
* Channel names with right-to-left characters are now casefolded correctly (thanks to [@remini1998](https://github.com/remini1998)!).
* Fixed handling of CIDR width in connection limiting/throttling.
* Fixed incorrect behavior of `CHANSERV OP` command.
* Fixed incorrect rejection of nickmasks with Unicode RTL nicknames.
* Fixed many responses that violated the specifications (thanks to [@Ascrod](https://github.com/Ascrod), [@bogdomania](https://github.com/bogdomania), [@csmith](https://github.com/csmith), [@jesopo](https://github.com/jesopo), and [@jwheare](https://github.com/jwheare)!).
* Fixed nickname sync issue which could cause clients to fail to see each other.
* Invalid `ISUPPORT` tokens are now explicitly rejected.
* Made `server-time` timestamp format more consistent and safer.
* Oragono now exits with status (1) if it fails to start.
* Prevent logging in multiple times when using `/NS IDENTIFY`.
* Prevented the db handler from automagically creating the database without initializing it (thanks [@enckse](https://github.com/enckse)!). We also now automatically create the datastore on `run`.

### Internal Notes
* `DLINE` and `KLINE` refactored, and expired bans are now removed from the database.
* Command-line parsing was upgraded to match modern best practices (thanks to [@iNecas](https://github.com/iNecas)!).
* Direct responses to client commands are now sent "synchronously", bypassing the sendq.
* Logging system optimised.
* Services handlers refactored.
* Translations are now sent to/PR'd from CrowdIn automagically as we develop the software.


## [0.12.0] - 2018-10-15
There's been a host of changes in the past six months, and this Halloween release has a number of very useful improvements.

For example, passwords are now hashed in a _much_ better way than we did it before (jlatt's original method back from [Ergonomadic](https://github.com/edmund-huber/ergonomadic) was the right way to do things), the database now auto-upgrades for you when it detects a new version, thanks to Slingamn we now have vhosts, and there's been a ton of rewrites under-the-hood to improve stability and performance.

If you have any trouble with this release, please let us know with an issue on our tracker, or by talking to us in `#oragono` on Freenode.

Thanks to [slingamn](https://github.com/slingamn) for a lot of heavy lifting this release and to [vilmibm](https://github.com/vilmibm) for contributing a documentation fix!

### Config Changes
* `allow-multiple-per-connection` key removed from `accounts`.
* `autoupgrade` key added under `datastore`, specifying whether to upgrade to new database versions automatically.
* `bcrypt-cost` key added under `accounts`, to control how strongly account passwords are hashed.
* `stackimpact` section removed from `debug`.
* `unix-bind-mode` key added under `server`, controlling the bind mode used for unix listening sockets.
* `vhosts` section added under `accounts`, configuring our new vhost support.
* new oper capabilities `accreg`, `sajoin`, `vhosts` and `chanreg` added.

### Security
* Password hashing has been improved (with current passwords being automatically upgraded to use the new method).
* Various crashes have been resolved.

### Added
* Added database auto-upgrades.
* Added new subcommands to `ChanServ` including:
    * `AMODE` to allow setting persistent channel modes for users.
    * `DROP` to unregister a channel.
* Added vhosts (virtual/vanity hosts), controlled via `HostServ`.

### Changed
* `ChanServ` and `NickServ` now show in their help output when commands have been disabled.
* Channel keys and modes are now stored for registered channels.
* Client capability handling rewritten under-the-hood.
* Disabled services commands now show as disabled (rather than being completely hidden).
* Many under-the-hood optimisations (thanks @slingamn!).
* Rehashing is now more consistent and safe.

### Removed
* Removed StackImpact debug support, as we don't find it useful these days.

### Fixed
* Fixed `LUSERS` to make it display correct client count and output correct params (thanks [@moortens](https://github.com/moortens)!.
* Fixed `PROXY` support for IPv6 clients.
* Fixed `SAMODE` crash when using it on a channel you're not joined to.
* Fixed `WHOIS` so that `RPL_WHOISACCOUNT` is now sent correctly.
* Fixed fakelag timing to better match expected values.
* Fixed issue where incoming and outgoing private messages were being incorrectly modified (a space was being added to the end) due to a bug with our protocol handling.
* Fixed password hashing method, with existing passwords being auto-upgraded to use the new method.


## [0.11.0] - 2018-04-15
And v0.11.0 finally comes along! This release has been in the works for almost four months now, with an alpha and beta helping square away the issues.

We're adding a lot of features to improve debugging, better support international users, and make things better for network administrators. Among the new features, you can use the `LANGUAGE` command to set a custom server language (see our [CrowdIn](https://crowdin.com/project/oragono) to contribute), expose a debugging `pprof` endpoint, reserve nicknames with `NickServ`, and force email verification for new user accounts. On the improvements side we have a `CAP REQ` fix, and we now have a manual that contains a nice overview of Oragono's documentation.

If you have any trouble with this release, please let us know with an issue on our tracker, or by talking to us in `#oragono` on Freenode.

Thanks a bunch to everyone for the help with this release – especially to our translators and to Slingamn for being an awesome co-maintainer!

### Config Changes
* `callbacks` section added under `accounts/registration`, configuring our new email verification (disabled by default).
* `fakelag` section added, configuring our new fakelag implementation.
* `ips-per-subnet` key renamed to `connections-per-subnet`.
* `motd-formatting` is now enabled by default.
* `nick-reservation` section added under `accounts`, configuring our new nickname ownership abilities.
* `nofakelag` and `unregister` oper classes added.
* `pprof-listener` key added under `debug` (disabled by default).
* `skip-server-password` key added under `accounts`, to better support certain clients.
* `verify-timeout` default value changed from 120 hours to 32 hours under `accounts/registration`.

### Added
* Added 32-bit builds.
* Added a debug pprof endpoint, which is disabled by default and can be exposed in the config.
* Added a manual to our documentation! This is primarily where we'll be adding user-facing information and instructions from now on.
* Added current running git commit to the sent version string.
* Added fakelag, so that the server can slow down clients hitting it too aggressively. Disabled by default while we work out the kinks and the specific settings (thanks @slingamn!).
* Added IRCv3 capability [`batch`](https://ircv3.net/specs/extensions/batch-3.2.html) and draft capability [`draft/labeled-response`](https://ircv3.net/specs/extensions/labeled-response.html).
* Added listening support for unix sockets.
* Added new Brazilian Portuguese translation (thanks to [Alexandre Oliveira](https://github.com/RockyTV)!)).
* Added new French translation (thanks to [Joshua](https://github.com/joshk0)!).
* Added new Norwegian translation (thanks to Morten!).
* Added new subcommands to `CHANSERV`, including:
    * `OP` to op yourself or the given user (can only be run by channel founders).
* Added new subcommands to `NICKSERV`, including:
    * `DROP` to de-associate a nickname from your current account.
    * `GHOST` to remove the given client (if they're logged in with your user account).
    * `GROUP` to associate a nickname with your current account.
    * `IDENTIFY` to login to an account.
    * `INFO` to see information about the given (or your own) account.
    * `REGISTER` to register an account.
    * `UNREGISTER` to delete your account.
* Added new Turkish translation (thanks to [Yaser](https://crowdin.com/profile/Apsimati)!).
* Added proposed IRCv3 capabilities [`draft/languages`](https://gist.github.com/DanielOaks/8126122f74b26012a3de37db80e4e0c6) and [`draft/resume`](https://github.com/ircv3/ircv3-specifications/pull/306).
* Added the ability to associate multiple nicknames with your account, and enforce nickname ownership.
* Added the ability to force email verification when users register accounts.
* Added user modes, including:
    * `B`: Mark yourself as a bot, and display that you're a bot in WHOIS.

### Changed
* `genpasswd` now requires that you confirm the input passphrase.
* Message IDs are now much shorter and easier to read – down from 39 characters to 16 while preserving a very similar gaurantee of uniqueness (thanks [@prawnsalad](https://github.com/prawnsalad) for bringing up this issue).

### Fixed
* We now correctly suspend registration when receiving a `CAP REQ`, as per [the spec](https://ircv3.net/specs/core/capability-negotiation-3.1.html).
* We now properly cut off clients who try to send us too much data at once.


## [0.10.3] - 2017-12-26
This patch fixes a couple bugs, updates cap/isupport token names in response to spec changes, and allows unprivileged users to list channel bans. Ah, DLINE and KLINE also store oper names, so you can see who set those pesky bans later on!

Overall, a fairly standard patch that just improves things. No config changes, no database changes.

Also, Merry Christmas and Happy Holidays!

### Added
* `DLINE`/`KLINE`: We now save the name of whichever oper set the ban (and display it later).

### Changed
* `draft/maxline` capability is now [`oragono.io/maxline`](https://oragono.io/maxline).
* `WHO`: First parameter now must be a mask or channel name, cannot be ommitted.
* Casemapping is now advertised using the `UTF8MAPPING` token, matching the new spec changes.
* We now allow unprivileged users to list channel bans.

### Fixed
* Fixed a bug around removing channel bans.
* Fixed a client timeout bug.


## [0.10.2] - 2017-11-13
This patch release fixes a bunch of crashes that were introduced in the last release, `0.10.1`.

If you have `0.10.1` running, replace it with this release.

### Security
* Fixed lots of miscellaneous crashes.


## [0.10.1] - 2017-11-09
This patch release of Oragono fixes a fairly big channel mode bug, where users could set channel modes when they weren't actually allowed to.

### Config Changes
* `recover-from-errors` key added under `debug`, which enables recovery from client-caused errors (at the cost of possible server instability).

### Security
* Clients could set channel modes when they weren't supposed to be able to.

### Added
* We now allow recovering from client-caused panics.

### Fixed
* `SAMODE` now lists other users' modes.
* Removed some possible crashes and races.


## [0.10.0] - 2017-10-23
There has been a bunch of new changes in this release! From [`sts`](http://ircv3.net/specs/extensions/sts.html) being ratified to supporting [`WEBIRC`](ircv3.net/specs/extensions/webirc.html) to rewriting a whole lot of our internals, 0.10.0 represents a real step forward in terms of where Oragono's going.

In addition to the new features, this issue fixes a bunch of fairly large bugs (such as an errant `INVITE` being able to crash the server, the `+mR`channel modes not working at all, and making rehashing safer).

I'd like to thank @slingamn for really contributing a lot in this release! He's done a whole bunch of the internal work, cleaned up the code, and in general just been a great help while developing. Running Oragono on an actual network has really helped find and track down some serious bugs, and lead us to some much-needed improvements.

### Config Changes
* `motd-formatting` key added under `server`, which supports MOTD formatting characters.
* `rest-api` section removed from `server` (since we no longer support the Rest API).
* `webirc` section added under `server`, which specifies the gateways can use the `WEBIRC` command.
* `ws-listen` key removed from `server` (since we no longer support websocket ports).
* Connection limits and connection throttling has become more relaxed by default.

### Security
* `INVITE`: Fixed a server crash when sending an invite for a channel that doesn't exist (thanks @josephbisch for telling me about the bug!).

### Added
* Added support for the [`WEBIRC`](ircv3.net/specs/extensions/webirc.html) command, allowing gateways to connect.
* We now list XLINEs with `DLINE LIST` and `KLINE LIST`.
* We now support using escaped formatting codes in the MOTD (tl;dr easy colors, bold and italics).

### Changed
* D-LINE and K-LINE code is now cleaner under the hood and less likely to crash.
* Ident (looking up usernames) now times out a whole lot quicker, meaning you connect to the server more quickly.
* IRCv3 capability `draft/sts` has been renamed to `sts`, since it's now been ratified.
* Rehashing is now safer.
* Server opers could always speak on channels, even when they shouldn't be able to. Now they aren't above the law.

### Removed
* Removed the `draft/message-ids` cap since... it doesn't actually exist. The feature is now enabled by default when clients request the `draft/message-tags-0.2` capability, as written in the [Message IDs spec](http://ircv3.net/specs/extensions/message-ids.html).
* Removed websocket support (conflicted with existing larger IRCd's implementations and not used by any real clients).
* REST API has been removed, until we can build up the web interface in parallel with it.

### Fixed
* `AWAY` was sending an incorrect mode string, and now sends the correct mode string (thanks @jwheare for pointing this out).
* Fixed some bugs with our `MONITOR` implementation which meant we weren't returning the right info to clients.
* The Moderated (`+m`) and RegisteredOnly (`+R`) channel modes could not be set. Now they can be set.


## [0.9.1] - 2017-09-28
This is a patch release to fix compatibility with Irssi and resolve some issues! Thanks very much @dequis, @slingamn and squigz for the help and for bringing up the issues.

### Added
* Allow the `MODE b` syntax, which certain clients use to check lists.

### Changed
* `QUIT`: We now send the actual quit message to other users.

### Fixed
* Fix incorrectly forwarding `AWAY` messages to clients without `away-notify`.
* Fix incorrect login check which prevented account registration.
* Fix `ERR_NOSUCHNICK` numerics (we weren't sending the nick correctly).


## [0.9.0] - 2017-09-25
So many fixes! You can now set the default modes for new channels, use HAProxy again, use the umode `+R` to protect yourself against unwanted PMs, and we now warn on configurations/setups that look incorrect!

In addition, this release makes testing easier, makes sure we better adhere to the SASL specification and also removes some memory leaks around the place. All in all, just a solid upgrade and less bugs across the board.

### Config Changes
* Added `allow-multiple-per-connection` flag under `accounts/registration`, which can be used for account setup by testing software. **Never enable it in production.**
* Added `default-modes` key under `channels`, which is a standard modestring that's applied to new channels.
* Added `proxy-allowed-from` key under `server`, which is a list of hostnames/IPs that the HAProxy `PROXY` command can be used from.

### Security
* Clients could use a nickname that isn't sane. This has the possibility of allowing clients to subvert our admin commands and monitoring features.

### Added
* Added a warning if the server's not listening on a TLS port or if it's not listening for TLS connections on port 6697.
* Added a warning if you're trying to run from source or an otherwise unreleased version.
* Added INFO.md document to better explain the design decisions behind Oragono, exactly how to rehash, etc.
* Added support for HAProxy's PROXY v1 command, useful for certain installations.
* Added user modes, including:
    * `R`: Only receive private messages and notices from other registered users.

### Fixed
* Fixed a bug where certain clients couldn't connect as we were incorrectly rejecting their valid PTR record (thanks @slingamn!).
* Fixed a crash around monitoring clients.
* Fixed a memory leak in our socket code when clients disconnect.
* Fixed a SASL bug that resulted in certains clients getting caught in a cycle of trying (and failing) to abort authentication.
* Fixed an instance where clients could use a nickname that isn't sane (thanks @euank!).
* Fixed an issue where certain clients who connect incorrectly would stay connected (thanks @euank!).
* Fixed how we handle particularly unique Unicode strings (we now ensure they stabilize while casefolding).
* Fixed some issues around rehashing, where listeners wouldn't rehash in time and could crash (thanks @slingamn!).


## [0.8.2] - 2017-06-30
Just a patch release to fix a bug! The bug that's been fixed prevented you from modifying channel privilidges at all, which isn't great. With this release, now you can do so again!

This is one I'm gonna have to add to [the testcases](https://github.com/DanielOaks/irctest), to make sure it doesn't happen again.

### Fixed
* Fixed a bug where users could not give other users operator/halfop/voice in channels.


## [0.8.1] - 2017-06-26
Lots of quality-of-life fixes, improved oversight for opers, and a proposed channel renaming command!

With this release, we're moving to a proper [Github organisation](https://github.com/oragono), becoming more consistent with other IRCds, and introducing a bunch more snomasks. In addition, when setting `DLINE` and `KLINE` bans, you can also kill all clients who match the ban by supplying the parameter `ANDKILL` when you set the ban.

Channel `LIST` filtering is now more useful, and I'll keep expanding this in future releases. As well, there's been some useful extensions to `WHOIS`, and a bug with `SANICK` fixed thanks to @lbeziaud. @enckse has also added Oragono to the Arch AUR, to make it easier to install on that distro.

Thanks to everyone for suggesting improvements and reporting issues! There's a lot to do as we move forward, and I have a pretty decent plan of where to go next.

### Added
* Added proposed channel rename capability [draft/rename](https://github.com/ircv3/ircv3-specifications/pull/308).
* Send a bunch more server notice masks, now including:
    * `j`: Channel registration.
    * `k`: Kills, including those resulting from `DLINE`s and `KLINE`s.
    * `n`: Nick changes.
    * `o`: Clients opering-up.
    * `q`: Clients quitting.
    * `u`: Account registration and login.
    * `x`: Setting and removing `DLINE`/`KLINE`.

### Changed
* `DLINE` and `KLINE`: Added `ANDKILL` parameter to also kill all clients that match the ban.
* `LIST`: Implement extended list conditions `U` (which filters the channels by user count).
* Renamed a number of dependency libraries, and changed Oragono to its' own organisation (only useful if you're building Oragono from source).
* `WHOIS`: Show the target's real IP address if you're whoising yourself or you're an oper.
* `WHOIS`: Show whether the target has connected securely using TLS.

### Removed
* Removed the `JOIN 0` command (matching what InspIRCd has done here), since this is easily abusable.

### Fixed
* `SANICK` works properly now (thanks @lbeziaud!).


## [0.8.0] - 2017-05-09
Debugging! Fixes! Better realtime monitoring!

This release isn't too exciting, but packs large improvements to how we handle floods and similar issues. As well, the introduction of snomasks (take a look at `/HELPOP snomasks`) should help opers keep a basic view over their server during use. Only the `"c"` (connects) snomask is active right now, but others will be added and extended in future releases.

### Config Changes
* Added `debug` section containing additional debug settings.
* Added `modes` key on oper config, for setting modes on oper-up.
* Added ability to log to `stdout` in logger methods.

### Added
* Added ability to log to stdout.
* Added ability to use StackImpact profiling.
* Added initial server notice masks (snomasks).

### Changed
* Socket code rewritten to be a lot faster and safer.
* Updated account registration to use the latest proposed syntax (now being `/ACC REGISTER` instead of `/REG CREATE`).

### Fixed
* Clients now timeout properly if they don't complete connection registration.
* Word wrapping (with `draft/maxline`) no longer randomly drops characters.


## [0.7.2] - 2017-04-17
This is a patch release of Oragono to fix discovered bugs and crashes. I'll also be implementing some more stringent checks before pushing releases after this, to ensure these same sort of bugs don't happen again.
 
### Security
* Fixed a bug where any user joining an unregistered channel was given chanop status (thanks @vegax87).
 
### Fixed
* Fixed a number of various crashes and races.


## [0.7.1] - 2017-03-28
This is a quick patch release of Oragono to work around a discovered bug.

### Security
* Fixed a bug where non-logged in users could register channels. Bleh.
 

## [0.7.0] - 2017-03-27
This release brings channel registration with ChanServ, logging improvements, and a whole host of improvements across the board.

Thanks to a suggestion by `dp-` on our channel (`#oragono` on Freenode), the socket handling code has been overhauled to allow for a larger number of more stable connections. As well, improved testing has brought with it a bunch of strange hang and crash fixes, which means that Oragono should be more stable than ever.

Channel registration is really cool. Essentially, you register the channel with `/CS REGISTER` as you would on any network, and then all topic changes, the `+b/+e/+I` lists, and your founder status, are all remembered and re-applied when the server's restarted.
 
### Config Changes
* `channels` section added to control channel registration.
* `logging` key under `server` removed, replaced with `logging` section.
* `max-sendq` key added under `server`.
* `registration` and `authentication-enabled` keys moved under `accounts` section.
* `samode` capability added to oper capabilities.
* `sts` section added under `server`.

### Added
* Added `ChanServ` service, to allow channel registration.
* Added `USERHOST` command (thanks @vegax87).
* Added `SAMODE` command.
* Added draft IRCv3 capability [draft/sts](http://ircv3.net/specs/core/sts-3.3.html).
 
### Changed
* `DLINE` and `KLINE` now let you specify years, months and days (e.g. `1y12m30d`) in durations.
* Logging is now much more useful, displays colours and can log to disk.
* Socket handling has been rewritten, which means we should support more connections more effectively (thanks dp- for the suggestion!).

### Fixed
* Fixed a bunch of small hangs and crashes.
* Fixed an account issue where clients could login to multiple accounts at once.
* Fixed an issue where server times were incorrect (thanks @martinlindhe!).
* Fixed halfops not being able to talk during moderated mode (`+m`).
* Fixed issues that prevented rehashing after the first rehash had gone through successfully.
* Fixed the inability to view channel ban, ban exception, and invite exception lists.


## [0.6.0] - 2017-01-19
We've added a ton of new features in this release! Automated connection throttling, the ability to `KLINE`, updated casemapping and line-length specifications.

I've also started including a new section in the changelog called **Config Changes**, which should help you find what you need to update across releases.

### Config Changes
* `enabled` key added under the `connection-limits` section.
* `connection-throttling` section added under `server`.
* `linelen` section added under `limits`.

### Added
* Added ARM build (for Raspberry PIs and similar).
* Added automated connection throttling! See the new `connection-throttling` section in the config.
* Added `KLINE` and `UNKLINE` commands. Complementing `DLINE`'s per-IP and per-network bans, this lets you ban masks from the server.
* Added `LUSERS` command (thanks @vegax87).
* Added draft IRCv3 capabilities [`draft/message-tags-0.2`](http://ircv3.net/specs/core/message-tags-3.3.html) and [`draft/message-ids`](http://ircv3.net/specs/extensions/message-ids.html).
* Added proposed IRCv3 capability [`draft/maxline`](https://github.com/ircv3/ircv3-specifications/pull/281).

### Changed
* Changed casemapping from "rfc7700" to "rfc7613", to match new draft spec.
* Connection limits can now be freely enabled or disabled. If updating, check the new `enabled` flag under the `connection-limits` section of the config.

### Fixed
* Fixed an issue where `UNDLINE` didn't save across server launches.
* Removed several race conditions which could result in server panics.
* WHOIS: Multiple channels now appear in a single reply (thanks @vegax87).


## [0.5.0] - 2016-12-10
This release includes a ton of fixes, as well as the ability to ban IP addresses from your network with the `DLINE` command!

As well, there are some major fixes with the libraries Oragono depends on, which fix various DoS attacks, crashes and timeouts. In short, this release is more stable and fixes a bunch of issues.

This release also updates the database, so be sure to run the `oragono upgradedb` command.

### Added
* Added ability to ban IP addresses and networks from the server with the `DLINE` and `UNDLINE` commands.
* Added alpha REST API (intended primarily for use with a future web interface to manage accounts, DLINEs, etc).

### Changed
* Database upgraded to make handling accounts simpler.
* Only give chanop (`@`) on channel join, not channel founder (`~`). We'll do channel founder and all on registered chans only.

### Fixed
* Fixed a bunch of bugs around setting nicknames on join.
* Fixed crash when using STATUSMSG-like messaging.
* Fixed crash with gIRC-Go ircmsg library we depend on.
* Fixed not sending `MODE` changes to all clients in a channel.
* Fixed timeout issue with go-ident library we depend on (which caused hangs on connection).
* Prevented a DoS related to lots of clients connecting at once.
* Removed races around setting and changing `NICK`s, to be more safe.
* Send channel `NOTICE`s properly.


## [0.4.0] - 2016-11-03
This release packs a more extensive oper privelege framework, bugfixes for capabilities/modes, support for new RP commands and more `RPL_ISUPPORT` tokens. In general, a bunch of new features and bugfixes to make using Oragono more smooth.

### Added
* Added automatic client connection limiting, similar to other IRCds.
* Added operator classes, allowing for more finely-grained permissions for operators.
* Added roleplaying commands, both inside channels and between clients.
* Length of channel mode lists (ban / ban-except / invite-except) is now restricted to the limit in config.
* Support `MAXLIST`, `MAXTARGETS`, `MODES`, `TARGMAX` in `RPL_ISUPPORT`.
* Added support for IRCv3 capability [`chghost`](http://ircv3.net/specs/extensions/chghost-3.2.html).

### Changed
* In the config file, "operator" changed to "opers", and new oper class is required.

### Fixed
* Fixed being able to change modes when not an operator.
* Fixed bug where `HELP` wouldn't correctly display for operators, and added more help topics.
* Fixed bug where you would always have certain capabilities enabled.
* Fixed display of large `MONITOR` lists.


## [0.3.0] - 2016-10-23
We now support dynamically reloading the config file, along with some new IRCv3 capabilities and some fixes.

The `REHASH` changes are fairly extensive here, but should now be stable (this also fixes a denial of service possible with the old code).

### Security
* Prevent a denial of service where the server would stop accepting connections.

### Added
* Added `REHASH` command.
* Added ability to message channel members with a specific privelege (i.e. support for `STATUSMSG`).
* Added ability to enable and disable SASL.
* Added support for IRCv3 capabilities [`cap-notify`](http://ircv3.net/specs/extensions/cap-notify-3.2.html) and [`echo-message`](http://ircv3.net/specs/extensions/echo-message-3.2.html).

### Changed
* Server operators no longer have permissions to do everything in channels.

### Fixed
* MODE: Fixed issue where channel privelege changes returned incorrectly.


## [0.2.0] - 2016-10-16
Improved compatibility, more features.

Now comes with a new proper Unicode-capable casemapping and integrated help!

### Added
* Added integrated help (with the `/HELP` command).
* Added support for IRCv3.2 [capability negotiation](http://ircv3.net/specs/core/capability-negotiation-3.2.html) including CAP values.
* Added support for IRCv3 capabilities [`account-notify`](http://ircv3.net/specs/extensions/account-notify-3.1.html), [`invite-notify`](http://ircv3.net/specs/extensions/invite-notify-3.2.html), [`monitor`](http://ircv3.net/specs/core/monitor-3.2.html), [`sasl`](http://ircv3.net/specs/extensions/sasl-3.2.html), and draft capability [`message-tags`](http://ircv3.net/specs/core/message-tags-3.3.html) as `draft/message-tags`.

### Changed
* Casemapping changed from custom unicode mapping to preliminary [rfc7700](https://github.com/ircv3/ircv3-specifications/pull/272) mapping.

### Removed
* Removed channel persistence with the `+P` mode (not too useful as currently implemented, to be replaced later).
* Removed the `PROXY` command (breaks our TLS user mode, and our integrated support for TLS should be fine).


## [0.1.0] - 2016-09-18
Initial release of Oragono!

### Security
* PROXY command is now restricted appropriately.
* Nicknames, usernames and channel names that break the protocol are no longer allowed.
* Default channel modes set to restrict new channels more appropriately by default.

### Added
* YAML config file format.
* buntdb key-value store for persistent data.
* Native SSL/TLS support (thanks to @edmand).
* Ability to generate testing certificates from the command line.
* Support for looking up usernames with [ident](https://tools.ietf.org/html/rfc1413) on client connection.
* [`RPL_ISUPPORT`](http://modern.ircdocs.horse/#rplisupport-005) numeric as advertised by most other IRCds today.
* Ability to parse complex mode change syntax commonly used these days (i.e. `+h-ov dan dan dan`).
* User mode for clients connected via TLS (`+Z`).
* Ability to register and login to accounts (with passphrase or certfp).
* Added support for IRCv3 capabilities [`account-tag`](http://ircv3.net/specs/extensions/account-tag-3.2.html), [`away-notify`](http://ircv3.net/specs/extensions/away-notify-3.1.html), [`extended-join`](http://ircv3.net/specs/extensions/extended-join-3.1.html), [`sasl`](http://ircv3.net/specs/extensions/sasl-3.1.html), [`server-time`](http://ircv3.net/specs/extensions/server-time-3.2.html), and [`userhost-in-names`](http://ircv3.net/specs/extensions/userhost-in-names-3.2.html).

### Changed
* Channel creator (`O`) privilege changed to founder/admin/halfops (`qah`) privileges.
* Private (`+p`) channel mode changed to secret (`+s`), to match what's used by servers today.
* Default channel modes changed to (`+nt`), matching most other IRCds.
* CLI commands and arguments made more consistent with typical software.
* Usernames set by the `USER` command now start with `"~"` (to work with new ident support).
* Renamed `ONICK` command to `SANICK` to be more consistent with other IRCds.
* Made maximum nickname and channel name lengths configurable.
* Made maximum `WHOWAS` entries configurable.

### Removed
* Removed gitconfig configuration format [replaced with YAML].
* Removed sqlite database [replaced with buntdb key-value store].
* Removed `THEATER` command (it broke and I'm not that interested in putting the work in to get it working again with the aim of this project. PRs accepted).

### Fixed
* Fixed clients no longer being able to send commands after a single command errored out.
* CAP: Registration is now properly suspended during CAP negotiation.
* CAP: Remove CAP CLEAR (recommended in IRCv3 3.2), and allow capability negotiation after registration.
* MODE: Fixed `<modestring>` evaluation (we were parsing all ungrabbed parameters as a modestring, when it is actually only the first param).
* MODE: New-style mode change syntax (with both adding and removing modes in a single MODE command) is now parsed properly.
* MOTD: Now store MOTD in-memory rather than on-disk, and don't limit it to 80 characters per line (not required with today's servers or clients).
* NICK: Restrict nicknames that break the protocol.
* USER: Restrict usernames that break the protocol.
* PROXY: Restrict to specified hostnames only.
* WHOIS: Include the required `<nick>` param on `RPL_ENDOFWHOIS`.
* WHOIS: Hide hidden channels in WHOIS responses.
