# Changelog
All notable changes to Oragono will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/). For the purposes of versioning, we consider the "public API" to refer to the configuration files, CLI interface and database format.


## Unreleased
Initial release of Oragono!

### Security
* PROXY command is now restricted appropriately.
* Nicknames, usernames and channel names that break the protocol are no longer allowed.
* Default channel modes set to restrict new channels more appropriately by default.

### Added
* Added YAML config file format.
* Added native SSL/TLS support (thanks to @edmand).
* Added ability to generate testing certificates from the command line.
* Added support for looking up usernames with [ident](https://tools.ietf.org/html/rfc1413) on client connection.
* Added [`RPL_ISUPPORT`](http://modern.ircdocs.horse/#rplisupport-005) numeric as advertised by most other IRCds today.
* Added ability to parse complex mode change syntax commonly used these days (i.e. `+h-ov dan dan dan`).
* Added user mode for clients connected via TLS (`+Z`).
* Added ability to register and login to accounts (with passphrase or certfp).
* Added support for IRCv3 capabilities [`account-tag`](http://ircv3.net/specs/extensions/account-tag-3.2.html), [`extended-join`](http://ircv3.net/specs/extensions/extended-join-3.1.html), [`sasl`](http://ircv3.net/specs/extensions/sasl-3.1.html), [`server-time`](http://ircv3.net/specs/extensions/server-time-3.2.html), and [`userhost-in-names`](http://ircv3.net/specs/extensions/userhost-in-names-3.2.html).

### Changed
* Changed channel creator (`O`) privilege to founder/admin/halfops (`qah`) privileges.
* Changed private (`+p`) channel mode to secret (`+s`), to match what's used by servers today.
* Changed default channel modes to (`+nt`), matching most other IRCds.
* Changed CLI commands and arguments to be more consistent with typical software.
* Changed usernames set by the `USER` command to start with `"~"` (to work with new ident support).
* Renamed `ONICK` command to `SANICK` to be more consistent with other IRCds.
* Made maximum nickname and channel name lengths configurable.
* Made maximum `WHOWAS` entries configurable.

### Removed
* Removed gitconfig configuration format [replaced with YAML].

### Fixed
* Fixed clients no longer being able to send commands after a single command errored out.
* CAP: Registration is now properly suspended during CAP negotiation.
* CAP: Remove CAP CLEAR, and allow capability negotiation after registration.
* MODE: Fixed `<modestring>` evaluation (we were parsing all ungrabbed parameters as a modestring, when it is actually only the first param).
* MODE: New-style mode change syntax (with both adding and removing modes in a single command) is now parsed properly.
* MOTD: Now store MOTD in-memory rather than on-disk, and don't limit it to 80 characters per line (not required with today's servers or clients).
* NICK: Restrict nicknames that break the protocol.
* PROXY: Restrict to specified hostnames only.
* USER: Restrict usernames that break the protocol.
* WHOIS: Include the required `<nick>` param on `RPL_ENDOFWHOIS`.
* WHOIS: Hide hidden channels in WHOIS responses.
