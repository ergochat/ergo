# Changelog
All notable changes to Oragono will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/). For the purposes of versioning, we consider the "public API" to refer to the configuration files, CLI interface and database format.


## Unreleased
Initial release of Oragono!

### Added
* Added YAML config file format.
* Added native SSL/TLS support (@edmand).
* We now advertise the [`RPL_ISUPPORT`](http://modern.ircdocs.horse/#rplisupport-005) numeric.
* Parse new mode change syntax commonly used these days (i.e. `+h-ov dan dan dan`).

### Changed
* Added channel Founder/Admin/Halfops (`qah`) privileges, and removed channel creator (`O`) privilege (from RFC2812, not used in the real world).
* CLI argument names made more consistent with typical software.

### Removed
* Gitconfig config format completely removed and replaced with YAML.

### Fixed
* CAP: Registration is now properly suspended during CAP negotiation.
* CAP: Remove CAP CLEAR, and allow capability negotiation after registration.
* MODE: Fixed `<modestring>` evaluation (we were parsing all ungrabbed parameters as a modestring, when it is actually only the first param).
* MODE: New-style mode change syntax (with both adding and removing modes in a single command) is now parsed properly.
* MOTD: Now store MOTD in-memory rather than on-disk, and don't limit it to 80 characters per line (not required with today's servers or clients).
* NICK: Improve nickname handling, restrict nicknames that break the protocol.
* WHOIS: Include the required `<nick>` param on `RPL_ENDOFWHOIS`.
