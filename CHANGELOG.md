# Changelog
All notable changes to Oragono will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/). For the purposes of versioning, we consider the "public API" to refer to the configuration files, CLI interface and database format.


## Unreleased
New release of Oragono!

### Security

### Added
* Added operator classes, allowing for more finely-grained permissions for operators.
* Added automatic client connection limiting, similar to other IRCds.
* Length of channel mode lists (ban / ban-except / invite-except) is now restricted to the limit in config.
* Support `MAXLIST`, `MAXTARGETS`, `MODES`, `TARGMAX` in `RPL_ISUPPORT`.
* Added support for IRCv3 capability [`chghost`](http://ircv3.net/specs/extensions/chghost-3.2.html).

### Changed
* In the config file, "operator" changed to "opers", and new oper class is required.

### Removed

### Fixed
* Fixed bug where `HELP` wouldn't correctly display for operators, and added more help topics.
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
