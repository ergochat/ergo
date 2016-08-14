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
* Added ability to generate certificates from the command line.
* Can now lookup usernames with ident on client connection.
* We now advertise the [`RPL_ISUPPORT`](http://modern.ircdocs.horse/#rplisupport-005) numeric.
* Parse new mode change syntax commonly used these days (i.e. `+h-ov dan dan dan`).
* User mode for clients connected via TLS (`+Z`).
* Support for [`extended-join`](http://ircv3.net/specs/extensions/extended-join-3.1.html).
* Support for [`server-time`](http://ircv3.net/specs/extensions/server-time-3.2.html).
* Support for [`userhost-in-names`](http://ircv3.net/specs/extensions/userhost-in-names-3.2.html).

### Changed
* Added channel Founder/Admin/Halfops (`qah`) privileges, and removed channel creator (`O`) privilege (from RFC2812, not used in the real world).
* Added secret (`+s`) channel mode to replace private (`+p`) for hiding channels, since everything else uses `+s` over `+p` these days.
* Default channel modes are now (`+nt`), matching most other IRCds.
* CLI argument names made more consistent with typical software.
* ONICK: Renamed to SANICK to be more consistent with other IRCds.
* USER: Prepend usernames set by the USER command with `"~"`.

### Removed
* Gitconfig config format completely removed and replaced with YAML.
* USER: No longer parse out the second and third parameters.

### Fixed
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
* Fixed clients no longer being able to send commands after a single command errored out.
