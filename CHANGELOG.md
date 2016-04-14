# Changelog

Notable changes to Oragono are listed in this file. The 'Unreleased' section may not always be up to date.

## Unreleased

* Initial release of Oragono!

### Added

* Added native SSL/TLS support (@edmand).
* Add [`RPL_ISUPPORT`](http://modern.ircdocs.horse/#rplisupport-005) support.

### Changed

* Gitconfig config format changed to YAML.
* Add Channel Founder/Admin/Halfops (`qah`) privileges, and remove Channel Creator (`O`) (privilege from 2812 that is not used in the real world).

### Fixes

* Improve nickname handling, restrict nicknames that break the protocol.
* CAP: Remove CAP CLEAR, and allow capability negotiation after registration.
* MOTD: Now store MOTD in-memory rather than on-disk, and don't limit it to 80 characters per line (not required with today's servers or clients).
* WHOIS: Include `<nick>` param on `RPL_ENDOFWHOIS`.
