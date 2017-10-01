# Changelog
All notable changes to Oragono will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/). For the purposes of versioning, we consider the "public API" to refer to the configuration files, CLI interface and database format.


## Unreleased
New release of Oragono!

### Config Changes

### Security

### Added

### Changed
* D-LINE and K-LINE code is now cleaner under the hood and less likely to crash.
* Rehashing is now safer.

### Removed
* Removed the `draft/message-ids` cap since... it doesn't actually exist. The feature is now enabled by default when clients request the `draft/message-tags-0.2` capability, as written in the [Message IDs spec](http://ircv3.net/specs/extensions/message-ids.html).
* Removed websocket support (conflicted with existing larger IRCd's implementations and not used by any real clients).

### Fixed
* `AWAY` was sending an incorrect mode string, and now sends the correct mode string.
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
