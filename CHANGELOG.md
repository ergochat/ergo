# Changelog
All notable changes to Ergo will be documented in this file.

## [2.11.0-rc1] - 2022-12-18

We're pleased to be publishing the release candidate for 2.11.0 (the official release should follow in a week or so). This is another bugfix release aimed at improving client compatibility and keeping up with the IRCv3 specification process.

This release includes changes to the config file format, all of which are fully backwards-compatible and do not require updating the file before upgrading. It includes no changes to the database file format.

Many thanks to dedekro, [@emersion](https://github.com/emersion), [@eskimo](https://github.com/eskimo), hauser, [@jwheare](https://github.com/jwheare), [@kingter-sutjiadi](https://github.com/kingter-sutjiadi), knolle, [@Mikaela](https://github.com/Mikaela), [@mogad0n](https://github.com/mogad0n), [@PeGaSuS-Coder](https://github.com/PeGaSuS-Coder), and [@progval](https://github.com/progval) for contributing patches, reporting issues, and helping test.

### Config changes

* Added `fakelag.command-budgets`, which allows each client session a limited number of specific commands that are exempt from fakelag. This improves compatibility with Goguma in particular. For the current recommended default, see `default.yaml` (#1978, thanks [@emersion](https://github.com/emersion)!)
* The recommended value of `server.casemapping` is now `ascii` instead of `precis`. PRECIS remains fully supported; if you are already running an Ergo instance, we do not recommend changing the value unless you are confident that your existing users are not relying on non-ASCII nicknames and channel names. (#1718)

### Changed

* Network services like `NickServ` now appear in `WHO` responses where applicable (#1850, thanks [@emersion](https://github.com/emersion)!)
* The `extended-monitor` capability now appears under its ratified name (#2006, thanks [@progval](https://github.com/progval)!)
* `TAGMSG` no longer receives automatic `RPL_AWAY` responses (#1983, thanks [@eskimo](https://github.com/eskimo)!)
* Sending `SIGUSR1` to the Ergo process now prints a full goroutine stack dump to stderr, allowing debugging even when the HTTP pprof listener is disabled (#1975)
* `UBAN` now states explicitly that bans without a time-limit have "indefinite" duration (#1988, thanks [@mogad0n](https://github.com/mogad0n)!)

### Fixed

* `WHO` with a bare nickname as an argument now shows invisible users, comparable to `WHOIS` (#1991, thanks [@emersion](https://github.com/emersion)!)
* MySQL did not work on 32-bit architectures; this has been fixed (#1969, thanks hauser!)
* Fixed the name of the `CHATHISTORY` 005 token (#2008, #2009, thanks [@emersion](https://github.com/emersion)!)
* Fixed handling of the address `::1` in WHOX output (#1980, thanks knolle!)
* Fixed handling of `AWAY` with an empty parameter (the de facto standard is to treat as a synonym for no parameter, which means "back") (#1996, thanks [@emersion](https://github.com/emersion), [@jwheare](https://github.com/jwheare)!)
* Fixed incorrect handling of some invalid modes in `CS AMODE` (#2002, thanks [@eskimo](https://github.com/eskimo)!)

### Added

* Added the `draft/persistence` capability and associated `PERSISTENCE` command. This is a first attempt to standardize Ergo's "always-on" functionality so that clients can interact with it programmatically (#1982)

### Internal

* Upgraded to Go 1.19; this makes further architecture-specific bugs like #1969 much less likely (#1987, #1989)
* The test suite is now parallelized (#1976, thanks [@progval](https://github.com/progval)!)


## [2.10.0] - 2022-05-29

We're pleased to be publishing v2.10.0, a new stable release.

This release contains no changes to the config file format or database file format.

Many thanks to [@csmith](https://github.com/csmith), [@FiskFan1999](https://github.com/FiskFan1999), [@Mikaela](https://github.com/Mikaela), [@progval](https://github.com/progval), and [@thesamesam](https://github.com/thesamesam) for contributing patches, and to [@emersion](https://github.com/emersion), [@eskimo](https://github.com/eskimo), [@FiskFan1999](https://github.com/FiskFan1999), [@jigsy1](https://github.com/jigsy1), [@Mikaela](https://github.com/Mikaela), [@mogad0n](https://github.com/mogad0n), [@progval](https://github.com/progval), and [@xnaas](https://github.com/xnaas) for reporting issues and helping test.

### Config changes

* For better interoperability with [Goguma](https://sr.ht/~emersion/goguma/), the recommended value of `history.chathistory-maxmessages` has been increased to `1000` (previously `100`) (#1919)

### Changed
* Persistent voice (`AMODE +v`) in a channel is now treated as a permanent invite (i.e. overriding `+i` on the channel) (#1901, thanks [@eskimo](https://github.com/eskimo)!)
* If you are `+R`, sending a direct message to an anonymous user allows them to send you replies (#1687, #1688, thanks [@Mikaela](https://github.com/Mikaela) and [@progval](https://github.com/progval)!)
* `0` is no longer valid as a nickname or account name, with a grandfather exception if it was registered on a previous version of Ergo (#1896)
* Implemented the [ratified version of the bot mode spec](https://ircv3.net/specs/extensions/bot-mode); the tag name is now `bot` instead of `draft/bot` (#1938)
* Privileged WHOX on a user with multiclient shows an arbitrarily chosen client IP address, comparable to WHO (#1897)
* `SAREGISTER` is allowed even under `DEFCON` levels 4 and lower (#1922)
* Operators with the `history` capability are now exempted from time cutoff restrictions on history retrieval (#1593, #1955)

### Added
* Added `draft/read-marker` capability, allowing server-side tracking of read messages for synchronization across multiple clients. (#1926, thanks [@emersion](https://github.com/emersion)!)
* `INFO` now includes the server start time (#1895, thanks [@xnaas](https://github.com/xnaas)!)
* Added `ACCEPT` command modeled on Charybdis/Solanum, allowing `+R` users to whitelist users who can DM them (#1688, thanks [@Mikaela](https://github.com/Mikaela)!)
* Added `NS SAVERIFY` for operators to manually complete an account verification (#1924, #1952, thanks [@tacerus](https://github.com/tacerus)!)

### Fixed
* Having the `samode` operator capability made all uses of the `KICK` command privileged (i.e. overriding normal channel privilege checks); this has been fixed (#1906, thanks [@pcho](https://github.com/pcho)!)
* Fixed `LIST <n` always returning no results (#1934, thanks [@progval](https://github.com/progval) and [@mitchr](https://github.com/mitchr)!)
* NickServ commands are now more clear about when a nickname is unavailable because it was previously registered and unregistered (#1886, thanks [@Mikaela](https://github.com/Mikaela)!)
* Fixed KLINE'd clients producing a `QUIT` snotice without a corresponding `CONNECT` snotice (#1941, thanks [@tacerus](https://github.com/tacerus), [@xnaas](https://github.com/xnaas)!)
* Fixed incorrect handling of long/multiline `319 RPL_WHOISCHANNELS` responses (#1935, thanks [@Mikaela](https://github.com/Mikaela)!)
* Fixed `LIST` returning `403 ERR_NOSUCHCHANNEL` for a nonexistent channel; the correct response is an empty list (#1928, thanks [@emersion](https://github.com/emersion)!)
* Fixed `+s` ("secret") channels not appearing in `LIST` even when the client is already a member (#1911, #1923, thanks [@jigsy1](https://github.com/jigsy1) and [@FiskFan1999](https://github.com/FiskFan1999)!)
* Fixed a spurious success message in `HISTSERV DELETE` by always requiring a consistent number of parameters (#1881, #1927, thanks [@FiskFan1999](https://github.com/FiskFan1999)!)
* Sending the empty string as a nickname would not always produce the expected error numeric `431 ERR_NONICKNAMEGIVEN`; this has been fixed (#1933, #1936, thanks [@kylef](https://github.com/kylef)!)
* `znc.in/playback` timestamps are now parsed as pairs of exact integers, not as floats (#1918)

### Internal
* Upgraded to Go 1.18 (#1925)
* Upgraded Alpine version in official Docker image
* Fixed some issues in the example OpenRC init scripts (#1914, #1920, thanks [@thesamesam](https://github.com/thesamesam)!)


## [2.9.1] - 2022-01-10

Ergo 2.9.1 is a bugfix release, fixing a regression introduced in 2.9.0. We regret the oversight.

This release includes no changes to the config file format or database format relative to 2.9.0.

Many thanks to [@FiskFan1999](https://github.com/FiskFan1999) for reporting the issue.

### Fixed
* Every use of NS SAREGISTER would fail; this has been fixed (#1898, thanks [@FiskFan1999](https://github.com/FiskFan1999)!)


## [2.9.0] - 2022-01-09

We're pleased to be publishing 2.9.0, a new stable release. This release contains mostly bug fixes, with some enhancements to moderation tools.

This release includes changes to the config file format, all of which are fully backwards-compatible and do not require updating the file before upgrading. It includes no changes to the database file format.

Many thanks to [@erincerys](https://github.com/erincerys), [@FiskFan1999](https://github.com/FiskFan1999), [@mogad0n](https://github.com/mogad0n), and [@tacerus](https://github.com/tacerus) for contributing patches, and to [@ajaspers](https://github.com/ajaspers), [@emersion](https://github.com/emersion), [@FiskFan1999](https://github.com/FiskFan1999), [@Jobe1986](https://github.com/Jobe1986), [@kylef](https://github.com/kylef), [@Mikaela](https://github.com/Mikaela), [@mogad0n](https://github.com/mogad0n), [@pcho](https://github.com/pcho), and [@progval](https://github.com/progval) for reporting issues and helping test.


### Config changes
* Added `lock-file`, which helps protect against accidentally starting multiple instances of Ergo. This is a no-op if unset. The recommended default value is `ircd.lock`, which (like the default datastore path `ircd.db`) is relative to the working directory of the Ergo process. If your `datastore.path` is absolute, this path (if set) should be absolute as well. (#1823)
* `+C` (no channel-wide CTCP messages other than ACTION) is now a recommended default channel mode (#1851)
* Added `exempt-sasl` boolean to `server.ip-check-script`; if enabled, IP check scripts are run only for connections without SASL, improving performance for registered users (#1888)
* `hidden: true` is now the recommended default for operator definitions (#1730)

### Changed
* The semantics of `+R` have been changed. `+R` now only prevents unauthenticated users from joining, so unregistered users who have already joined can still speak. The old semantics are still available via `+RM` (i.e. `+R` together with the `+M` "moderated-registered" mode). (#1858, thanks [@ajaspers](https://github.com/ajaspers)!)
* Unauthenticated users matching a `+I` invite exception mask can now join `+R` channels (#1871)
* INVITE now exempts the user from `+b` bans (#1876, thanks [@progval](https://github.com/progval)!)
* NS SUSPEND now only requires only the `ban` operator capability, as opposed to `accreg` (#1828, #1839, thanks [@mogad0n](https://github.com/mogad0n)!)

### Added
* SHA-256 certificate fingerprints can now be imported from Anope and Atheme (#1864, #1869, thanks [@tacerus](https://github.com/tacerus)!)
* IP check scripts can now be run only for users that have not authenticated with SASL by the end of the handshake, improving performance for registered users (#1888)
* Logging into an unverified account with SASL sends the new `NOTE AUTHENTICATE VERIFICATION_REQUIRED` [standard reply code](https://ircv3.net/specs/extensions/standard-replies) (#1852, #1853, thanks [@emersion](https://github.com/emersion)!)
* CS PURGE now sends a snotice (#1826, thanks [@tacerus](https://github.com/tacerus)!)
* The `v` snomask is now used to send notifications about vhost changes initiated by operators (#1844, thanks [@pcho](https://github.com/pcho)!)

### Fixed
* CAP LS and LIST responses after connection registration could be truncated in some cases; this has been fixed (#1872)
* Unprivileged users with both a password and a certfp could not remove their password with `NS PASSWD <password> * *` as expected; this has been fixed (#1883, #1884, thanks [@FiskFan1999](https://github.com/FiskFan1999)!)
* RELAYMSG identifiers that were not already in their case-normalized form could not be muted with `+b m:`; this has been fixed (#1838, thanks [@mogad0n](https://github.com/mogad0n)!)
* CS AMODE changes did not take immediate effect if `force-nick-equals-account` was disabled and the nick did not coincide with the account; this has been fixed (#1860, thanks [@eskimo](https://github.com/eskimo)!)
* `315 RPL_ENDOFWHO` now sends the exact, un-normalized mask argument provided by the client (#1831, thanks [@progval](https://github.com/progval)!)
* A leading `$` character is now disallowed in new nicknames and account names, to avoid collision with the massmessage syntax (#1857, thanks [@emersion](https://github.com/emersion)!)
* The [deprecated](https://github.com/ircdocs/modern-irc/pull/138) `o` parameter of `WHO` now returns an empty list of results, instead of being ignored (#1730, thanks [@kylef](https://github.com/kylef), [@emersion](https://github.com/emersion), [@progval](https://github.com/progval)!)
* WHOX queries for channel oplevel now receive `*` instead of `0` (#1866, thanks [@Jobe1986](https://github.com/Jobe1986)!)

### Internal
* Updated list of official release binaries: added Apple M1, OpenBSD x86-64, and Plan 9 x86-64, removed Linux armv7, FreeBSD x86-32, and Windows x86-32. (The removed platforms are still fully supported by Ergo; you can build them from source or ask us for help.) (#1833)
* Added an official Linux arm64 Docker image (#1855, thanks [@erincerys](https://github.com/erincerys)!)
* Added service management files for OpenSolaris/Illumos (#1846, thanks [@tacerus](https://github.com/tacerus)!)


## [2.8.0] - 2021-11-14

We're pleased to be publishing Ergo 2.8.0. This release contains many fixes and enhancements, plus one major user-facing feature: user-initiated password resets via e-mail (#734).

This release includes changes to the config file format, all of which are fully backwards-compatible and do not require updating the file before upgrading.

This release includes a database change. If you have `datastore.autoupgrade` set to `true` in your configuration, it will be automatically applied when you restart Ergo. Otherwise, you can update the database manually by running `ergo upgradedb` (see the manual for complete instructions).

As part of this release, our official Docker images have moved from Docker Hub to the GitHub Container Registry, at `ghcr.io/ergochat/ergo`. The `stable` and `master` tags correspond to the respective branches. Tagged releases (e.g. `v2.8.0`) are available under the corresponding named tags.

Many thanks to [@ajaspers](https://github.com/ajaspers), [@delthas](https://github.com/delthas), [@mogad0n](https://github.com/mogad0n), [@majiru](https://github.com/majiru), [@ProgVal](https://github.com/ProgVal), and [@tacerus](https://github.com/tacerus) for contributing patches, to [@ajaspers](https://github.com/ajaspers) for contributing code review, to [@ajaspers](https://github.com/ajaspers), [@cxxboy](https://github.com/cxxboy), [@dallemon](https://github.com/dallemon), [@emersion](https://github.com/emersion), [@erikh](https://github.com/erikh), [@eskimo](https://github.com/eskimo), [@jwheare](https://github.com/jwheare), [@kylef](https://github.com/kylef), [@Mikaela](https://github.com/Mikaela), [@mogad0n](https://github.com/mogad0n), [@MystaraTheGreat](https://github.com/MystaraTheGreat), [@ProgVal](https://github.com/ProgVal), [@tacerus](https://github.com/tacerus), [@tamiko](https://github.com/tamiko), and [@xnaas](https://github.com/xnaas) for reporting issues and helping test, and to our translators for contributing translations.

### Config changes
* Added `accounts.registration.email-verification.password-reset` block to configure e-mail-based password reset (#734, #1779)
* Added `accounts.registration.email-verification.timeout` to impose a timeout on e-mail sending; the recommended default value is `60s` (60 seconds) (#1741)
* Added `server.suppress-lusers` to allow hiding the LUSERS counts (#1802, thanks [@eskimo](https://github.com/eskimo)!)

### Security
* Added `accounts.registration.email-verification.timeout` to impose a timeout on e-mail sending; the recommended default value is `60s` (60 seconds) (#1741)

### Added
* Added user-initiated password resets via email (#734). This requires e-mail verification of accounts, and must additionally be enabled explicitly: see the `email-verification` block in `default.yaml` for more information.
* Added the `draft/extended-monitor` capability (#1761, thanks [@delthas](https://github.com/delthas)!)
* When doing direct sending of verification emails, make email delivery failures directly visible to the end user (#1659, #1741, thanks [@tacerus](https://github.com/tacerus)!)
* For operators, `NS INFO` now shows the user's email address (you can also view your own address) (#1677, thanks [@ajaspers](https://github.com/ajaspers)!)
* Operators with the appropriate permissions will now see IPs in `/WHOWAS` output (#1702, thanks [@ajaspers](https://github.com/ajaspers)!)
* Added the `+s d` snomask, for operators to receive information about session disconnections that do not result in a full QUIT (#1709, #1728, thanks [@mogad0n](https://github.com/mogad0n)!)
* Added support for the `SCRAM-SHA-256` SASL authentication mechanism (#175). This mechanism is not currently advertised in `CAP LS` output because IRCCloud handles it incorrectly. We also [recommend against using SCRAM because of its lack of genuine security benefits](https://gist.github.com/slingamn/3f2fed196df5ef14d1316a1ffa9d59f8).
* `/UBAN LIST` output now includes the time the ban was created (#1725, #1755, thanks [@Mikaela](https://github.com/Mikaela) and [@mogad0n](https://github.com/mogad0n)!)
* Added support for running as a `Type=notify` systemd service (#1733)
* Added a warning to help users detect incorrect uses of `/QUOTE` (#1530)

### Fixed
* The `+M` (only registered users can speak) channel mode did not work; this has been fixed (#1696, thanks [@Mikaela](https://github.com/Mikaela)!)
* A channel `/RENAME` that only changed the case of the channel would delete the channel registration; this has been fixed (#1751, thanks [@Mikaela](https://github.com/Mikaela)!)
* Fixed `allow-truncation: true` not actually allowing truncation of overlong lines (#1766, thanks [@tacerus](https://github.com/tacerus)!)
* Fixed several pagination bugs in `CHATHISTORY` (#1676, thanks [@emersion](https://github.com/emersion)!)
* Fixed support for kicking multiple users from a channel on the same line, the `TARGMAX` 005 parameter that advertises this, and the default kick message (#1748, #1777, #1776), thanks [@ProgVal](https://github.com/ProgVal)!)
* Fixed `/SAMODE` on a channel not producing a snomask (#1787, thanks [@mogad0n](https://github.com/mogad0n), [@ajaspers](https://github.com/ajaspers)!)
* Adding `+f` to a channel with `SAMODE` used to require channel operator privileges on the receiving channel; this has been fixed (#1825, thanks [@Mikaela](https://github.com/Mikaela)!)
* Fixed parameters sent with `697 ERR_LISTMODEALREADYSET` and `698 ERR_LISTMODENOTSET` (#1727, thanks [@kylef](https://github.com/kylef)!)
* Fixed parameter sent with `696 ERR_INVALIDMODEPARAM` (#1773, thanks [@kylef](https://github.com/kylef)!)
* Fixed handling of channel mode `+k` with an empty parameter (#1774, #1775, thanks [@ProgVal](https://github.com/ProgVal)!)
* `WHOWAS` with an empty string as the parameter now produces an appropriate error response (#1703, thanks [@kylef](https://github.com/kylef)!)
* Fixed error response to an empty realname on the `USER` line (#1778, thanks [@ProgVal](https://github.com/ProgVal)!)
* Fixed `/UBAN ADD` of a NUH mask (i.e. a k-line) not killing affected clients (#1736, thanks [@mogad0n](https://github.com/mogad0n)!)
* Fixed buggy behavior when `+i` is configured as a default mode for channels (#1756, thanks [@Mikaela](https://github.com/Mikaela)!)
* Fixed issues with `channels.operator-only-creation` not respecting `/SAJOIN` or always-on clients (#1757)
* Protocol-breaking operator vhosts are now disallowed during config validation (#1722)
* Fixed error message associated with `/NS PASSWD` on a nonexistent account (#1738, thanks [@Mikaela](https://github.com/Mikaela)!)
* Fixed an incorrect `CHATHISTORY` fail message (#1731, thanks [@ProgVal](https://github.com/ProgVal)!)
* Fixed a panic on an invalid configuration case (#1714, thanks [@erikh](https://github.com/erikh)!)

### Changed
* Upgraded the `draft/register` capability to the latest [`draft/account-registration`](https://github.com/ircv3/ircv3-specifications/pull/435) iteration (#1740)
* Unregistered users with `+v` or higher can now speak in `+R` (registered-only) channels (#1715, thanks [@Mikaela](https://github.com/Mikaela) and [@ajaspers](https://github.com/ajaspers)!)
* For always-on clients with at least one active connection, `338 RPL_WHOISACTUALLY` now displays an arbitrarily chosen client IP address (#1650, thanks [@MystaraTheGreat](https://github.com/MystaraTheGreat)!)
* `#` can no longer be used in new account names and nicknames, or as the RELAYMSG separator (#1679)
* The `oragono.io/nope` capability was renamed to `ergo.chat/nope` (#1793)

### Removed
* `never` is no longer accepted as a value of the `replay-joins` NickServ setting (`/NS SET replay-joins`); user accounts which enabled this setting have been reverted to the default value of `commands-only` (#1676)

### Internal
* We have a cool new logo!
* Official builds now use Go 1.17 (#1781)
* Official Docker containers are now at [ghcr.io/ergochat/ergo](https://ghcr.io/ergochat/ergo) (#1808)
* Added a traditional SysV init script (#1691, thanks [@tacerus](https://github.com/tacerus)!)
* Added an s6 init script (#1786, thanks [@majiru](https://github.com/majiru)!)

## [2.7.0] - 2021-06-07

We're pleased to be publishing Ergo 2.7.0, our first official release under our new name of Ergo. This release contains bug fixes and minor enhancements.

This release includes changes to the config file format, all of which are fully backwards-compatible and do not require updating the file before upgrading. This release includes no changes to the database format.

Because the name of the executable has changed from `oragono` to `ergo` (`ergo.exe` on Windows), you may need to update your system configuration (e.g., scripts or systemd unit files that reference the executable).

Many thanks to [@ajaspers](https://github.com/ajaspers) and [@jesopo](https://github.com/jesopo) for contributing patches, to [@ajaspers](https://github.com/ajaspers), [@ChrisTX](https://github.com/ChrisTX), [@emersion](https://github.com/emersion), [@jwheare](https://github.com/jwheare), [@kylef](https://github.com/kylef), [@Mikaela](https://github.com/Mikaela), [@mogad0n](https://github.com/mogad0n), and [@ProgVal](https://github.com/ProgVal) for reporting issues and helping test, and to our translators for contributing translations.

### Changed
* The project was renamed from "Oragono" to "Ergo" (#897, thanks to everyone who contributed feedback or voted in the poll)

### Config changes
* Entries in `server.listeners` now take a new key, `min-tls-version`, that can be used to set the minimum required TLS version; the recommended default value is `1.2` (#1611, thanks [@ChrisTX](https://github.com/ChrisTX)!)
* Added `max-conns` (maximum connection count) and `max-conn-lifetime` (maximum lifetime of a connection before it is cycled) to `datastore.mysql` (#1622)
* Added `massmessage` operator capability to allow sending NOTICEs to all connected users (#1153, #1629, thanks [@jesopo](https://github.com/jesopo)!)

### Security
* If `require-sasl.enabled` is set to `true`, `tor-listeners.require-sasl` will be automatically set to `true` as well (#1636)
* It is now possible to set the minimum required TLS version, using the `min-tls-version` key in listener configuration
* Configurations that require SASL but allow user registration now produce a warning (#1637)

### Added:
* Operators with the correct permissions can now send "mass messages", e.g. `/NOTICE $$*` will send a `NOTICE` to all users (#1153, #1629, thanks [@jesopo](https://github.com/jesopo)!)
* Operators can now extend the maximum (non-tags) length of the IRC line using the `server.max-line-len` configuration key. This is not recommended for use outside of "closed-circuit" deployments where IRC operators have full control of all client software. (#1651)

### Fixed
* `RELAYMSG` now sends a full NUH ("nick-user-host"), instead of only the relay nickname, as the message source (#1647, thanks [@ProgVal](https://github.com/ProgVal), [@jwheare](https://github.com/jwheare), and [@Mikaela](https://github.com/Mikaela)!)
* Fixed a case where channels would remain visible in `/LIST` after unregistration (#1619, thanks [@ajaspers](https://github.com/ajaspers)!)
* Fixed incorrect tags on `JOIN` lines in `+u` ("auditorium") channels (#1642)
* Fixed an issue where LUSERS counts could get out of sync (#1617)
* It was impossible to add a restricted set of snomasks to an operator's permissions; this has been fixed (#1618)
* Fixed incorrect language in `NS INFO` responses (#1627, thanks [@ajaspers](https://github.com/ajaspers)!)
* Fixed a case where the `REGISTER` command would emit an invalid error message (#1633, thanks [@ajaspers](https://github.com/ajaspers)!)
* Fixed snomasks displaying in a nondeterministic order (#1669, thanks [@Mikaela](https://github.com/Mikaela)!)

### Removed
* Removed the `draft/resume-0.5` capability, and the associated `RESUME` and `BRB` commands (#1624)

### Internal
* Optimized MySQL storage of direct messages (#1615)

## [2.6.1] - 2021-04-26

Oragono 2.6.1 is a bugfix release, fixing a security issue that is critical for some private server configurations. We regret the oversight.

The issue affects two classes of server configuration:

1. Private servers that use `server.password` (i.e., the `PASS` command) for protection. If `accounts.registration.allow-before-connect` is enabled, the `REGISTER` command can be used to bypass authentication. Affected operators should set this field to `false`, or upgrade to 2.6.1, which disallows the insecure configuration. (If the field does not appear in the configuration file, the configuration is secure since the value defaults to false when unset.)
2. Private servers that use `accounts.require-sasl` for protection. If these servers do not additionally set `accounts.registration.enabled` to `false`, the `REGISTER` command can potentially be used to bypass authentication. Affected operators should set `accounts.registration.enabled` to false; this recommendation appeared in the operator manual but was not emphasized sufficiently. (Configurations that require SASL but allow open registration are potentially valid, e.g., in the case of public servers that require everyone to use a registered account; accordingly, Oragono 2.6.1 continues to permit such configurations.)

This release includes no changes to the config file format or the database.

Many thanks to [@ajaspers](https://github.com/ajaspers) for reporting the issue.

### Security
* Fixed and documented potential authentication bypasses via the `REGISTER` command (#1634, thanks [@ajaspers](https://github.com/ajaspers)!)

## [2.6.0] - 2021-04-18

We're pleased to announce Oragono 2.6.0, a new stable release.

This release has some user-facing enhancements, but is primarily focused on fixing bugs and advancing the state of IRCv3 standardization (by publishing a release that implements the latest drafts). Some highlights:

* A new CHATHISTORY API for listing direct message conversations (#1592)
* The latest proposal for IRC-over-websockets, which should be backwards-compatible with existing clients (#1558)
* The latest specification for the bot usermode (`+B` in our implementation) (#1562)

This release includes changes to the config file format, all of which are fully backwards-compatible and do not require updating the file before upgrading.

This release includes no changes to the embedded database format. If you are using MySQL for history storage, it adds a new table; this change is backwards and forwards-compatible and does not require any manual intervention.

If you are using nginx as a reverse proxy for IRC-over-websockets, previous documentation did not recommend increasing `proxy_read_timeout`; the default value of `60s` is too low and can lead to user disconnections. The current recommended value is `proxy_read_timeout 600s;`; see the manual for an example configuration.

Many thanks to [@ajaspers](https://github.com/ajaspers) and [@Mikaela](https://github.com/Mikaela) for contributing patches, to [@aster1sk](https://github.com/aster1sk), [@emersion](https://github.com/emersion), [@eskimo](https://github.com/eskimo),  [@hhirtz](https://github.com/hhirtz), [@jlu5](https://github.com/jlu5), [@jwheare](https://github.com/jwheare), [@KoraggKnightWolf](https://github.com/KoraggKnightWolf), [@kylef](https://github.com/kylef), [@Mikaela](https://github.com/Mikaela), [@mogad0n](https://github.com/mogad0n), [@ProgVal](https://github.com/ProgVal), and [@szlend](https://github.com/szlend) for reporting issues and helping test, and to our translators for contributing translations.

### Config changes
* Listeners now support multiple TLS certificates for use with SNI; see the manual for details (#875, thanks [@Mikaela](https://github.com/Mikaela)!)
* Added `server.compatibility.allow-truncation`, controlling whether the server accepts messages that are too long to be relayed intact; this value defaults to `true` when unset (#1577, #1586, thanks [@kylef](https://github.com/kylef)!)
* Added new `snomasks` operator capability; operators must have either the `ban` or `snomasks` capability to subscribe to additional snomasks (#1176)

### Security
* Fixed several edge cases where Oragono might relay invalid UTF8 despite the `UTF8ONLY` guarantee, or to a text-mode websocket client (#1575, #1596, thanks [@ProgVal](https://github.com/ProgVal)!)
* All operator privilege checks now use the capabilities system, making it easier to define operators with restricted powers (#1176)
* Adding and removing bans with `UBAN` now produces snomasks and audit loglines (#1518, thanks [@mogad0n](https://github.com/mogad0n)!)

### Fixed
* Fixed an edge case in line buffering that could result in client disconnections (#1572, thanks [@ProgVal](https://github.com/ProgVal)!)
* Upgraded buntdb, our embedded database library, fixing an edge case that could cause data corruption (#1603, thanks [@Mikaela](https://github.com/Mikaela), [@tidwall](https://github.com/tidwall)!)
* Improved compatibility with the published `draft/register` specification (#1568, thanks [@ProgVal](https://github.com/ProgVal)!)
* `433 ERR_NICKNAMEINUSE` is no longer sent when a fully connected ("registered") client fails to claim a reserved nickname, fixing a bad interaction with some client software (#1594, thanks [@ProgVal](https://github.com/ProgVal)!)
* Fixed `znc.in/playback` commands causing client disconnections when history is disabled (#1552, thanks [@szlend](https://github.com/szlend)!)
* Fixed syntactically invalid `696 ERR_INVALIDMODEPARAM` response for invalid channel keys (#1563, thanks [@ProgVal](https://github.com/ProgVal)!)
* User-set nickserv settings now display as "enabled" instead of "mandatory" (#1544, thanks [@Mikaela](https://github.com/Mikaela)!)
* Improved error messages for some invalid configuration cases (#1559, thanks [@aster1sk](https://github.com/aster1sk)!)
* Improved `CS TRANSFER` error messages (#1534, thanks burning!)
* Handle panics caused when rehashing with SIGHUP (#1570)

### Changed
* Registered channels will always appear in `/LIST` output, even with no members (#1507)
* In the new recommended default configuration, Oragono will preemptively reject messages that are too long to be relayed to clients without truncation. This is controlled by the config variable `server.compatibility.allow-truncation`; this field defaults to `true` when unset, preserving the legacy behavior for older config files (#1577, #1586, thanks [@kylef](https://github.com/kylef)!)
* Auto-away behavior now respects individual clients; the user is not considered away unless all clients are away or disconnected (#1531, thanks [@kylef](https://github.com/kylef)!)
* Direct messages rejected due to the `+R` registered-only usermode now produce an error message (#1064, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf), [@ajaspers](https://github.com/ajaspers)!)
* RELAYMSG identifiers now respect bans and mutes (#1502)
* If end user message deletion is enabled, channel operators can now delete channel messages (#1565, thanks [@Mikaela](https://github.com/Mikaela)!)
* Halfops can change the channel topic (#1523)
* Snomask add/remove syntax now matches other ircds more closely (#1074)
* `CS OP` will regrant your channel `AMODE`, in case you removed it (#1516, #1307, thanks [@jlu5](https://github.com/jlu5)!)
* User passwords may no longer begin with `:` (#1571)
* Improved documentation of `CS AMODE` and `NS UNREGISTER` (#1524, #1545, thanks [@Mikaela](https://github.com/Mikaela)!)
* Disabling history disables history-related CAPs (#1549)

### Added
* Implemented the new [CHATHISTORY TARGETS](https://github.com/ircv3/ircv3-specifications/pull/450) API for listing direct message conversations (#1592, thanks [@emersion](https://github.com/emersion), [@hhirtz](https://github.com/hhirtz), [@jwheare](https://github.com/jwheare), [@kylef](https://github.com/kylef)!)
* Implemented the new [IRC-over-websockets draft](https://github.com/ircv3/ircv3-specifications/pull/342), adding support for binary websockets and subprotocol negotiation (#1558, thanks [@jwheare](https://github.com/jwheare)!)
* Implemented the new [bot mode spec](https://github.com/ircv3/ircv3-specifications/pull/439) (#1562)
* Implemented the new [forward mode spec](https://github.com/ircv3/ircv3-specifications/pull/440) (#1612, thanks [@ProgVal](https://github.com/ProgVal)!)
* `WARN NICK ACCOUNT_REQUIRED` is sent on failed attempts to claim a reserved nickname (#1594)
* `NS CLIENTS LIST` displays enabled client capabilities (#1576)
* `CS INFO` with no arguments lists your registered channels (#765)
* `NS PASSWORD` is now accepted as an alias for `NS PASSWD` (#1547)

### Internal
* Upgraded to Go 1.16 (#1510)

## [2.5.1] - 2021-02-02

Oragono 2.5.1 is a bugfix release that fixes a significant security issue. We apologize for the oversight.

This release includes no changes to the config file format or the database.

Many thanks to [@xnaas](https://github.com/xnaas) for reporting the issue.

### Security
* Fix an incorrect permissions check in NickServ (#1520, thanks [@xnaas](https://github.com/xnaas)!)

## [2.5.0] - 2021-01-31

We're pleased to announce Oragono 2.5.0, a new stable release.

This release includes enhancements based on the needs of real-world operators, as well as bug fixes. Highlights include:

* `UBAN`, a new "unified ban" system for server operators, with a corresponding `CHANSERV HOWTOBAN` command for channel operators (#1447)
* A new forwarding/overflow channel mode `+f` (#1260)
* Support for PROXY protocol v2 (#1389)

This release includes changes to the config file format, including two breaking changes. One is fairly significant: enabling a websocket listener now requires the use of `server.enforce-utf8`, as has been the recommended default since 2.2.0 (so continuing to accept legacy non-UTF-8 content will require disabling websockets). The other is that the "unban" operator capability has been removed (it is now included in the "ban" capability). Other config changes are backwards compatible and do not require updating the file before upgrading.

This release includes a database change. If you have `datastore.autoupgrade` set to `true` in your configuration, it will be automatically applied when you restart Oragono. Otherwise, you can update the database manually by running `oragono upgradedb` (see the manual for complete instructions).

Many thanks to [@jlu5](https://github.com/jlu5), [@kylef](https://github.com/kylef) and [@Mikaela](https://github.com/Mikaela) for contributing patches, to [@bogdomania](https://github.com/bogdomania), [@eskimo](https://github.com/eskimo), [@happyhater](https://github.com/happyhater), [@jlu5](https://github.com/jlu5), [@kylef](https://github.com/kylef), [@LukeHoersten](https://github.com/LukeHoersten), [@Mikaela](https://github.com/Mikaela), [@mogad0n](https://github.com/mogad0n), [@robinlemon](https://github.com/robinlemon), and [@vertisan](https://github.com/vertisan) for reporting issues and helping test, and to our translators for contributing translations.

### Config changes
* Enabling websockets now requires `server.enforce-utf8 = true` (#1483)
* `proxy` is now a top-level field of the listener config block; in particular, the PROXY protocol (v1 or v2) can now be required ahead of a plaintext connection. The field is still accepted in its legacy position (inside the `tls` block). (#1389, thanks [@robinlemon](https://github.com/robinlemon)!)
* Added `accounts.multiclient.always-on-expiration`, allowing always-on clients to be timed out for inactivity (#810, thanks [@bogdomania](https://github.com/bogdomania)!)
* `local_` prefixes have been stripped from operator capability names, so that, e.g., `local_ban` is now just `ban`. The old names are still accepted. (#1442)
* The `local_unban` operator capability has been removed (unbanning is now contained in the `ban` permission). (#1442)
* The recommended value of `accounts.bcrypt-cost` is now `4`, the minimum acceptable value (#1497)
* `server.ip-limits.custom-limits` now accepts networks that contain multiple CIDRs; the old syntax is still accepted (#1421, thanks [@Mikaela](https://github.com/Mikaela)!
* A new field, `history.restrictions.query-cutoff`, generalizes the old `history.restrictions.enforce-registration-date` (the old field is still accepted) (#1490, thanks [@Mikaela](https://github.com/Mikaela)!)
* Added `server.override-services-hostname`, allowing the hostname of NickServ, ChanServ, etc. to be overridden (#1407, thanks [@Mikaela](https://github.com/Mikaela)!)
* Added a boolean `hide-sts` key to the listener block; this can be used to hide the STS CAP when the listener is secured at layer 3 or 4 (e.g., by a VPN or an E2E mixnet). It will still be necessary to add the relevant IPs to `secure-nets`. (#1428, thanks [@Mikaela](https://github.com/Mikaela)!)

### Security
* Improved validation of names and encodings for client-only tags (#1385)
* Improved auditability of sensitive operator actions (#1443, thanks [@mogad0n](https://github.com/mogad0n)!)
* `DEFCON 4` and lower now require Tor users to authenticate with SASL (#1450)

### Fixed
* Fixed `NS UNSUSPEND` requiring the casefolded / lowercase version of the account name (#1382, thanks [@mogad0n](https://github.com/mogad0n)!)
* Fixed client-only tags in direct (user-to-user) `PRIVMSG` not being replayed (#1411)
* Fixed many bugs in import of Anope and Atheme databases (#1403, #1423, #1424, #1431, #1435, #1439, #1444, thanks [@jlu5](https://github.com/jlu5), [@kylef](https://github.com/kylef), and [@Mikaela](https://github.com/Mikaela)!)
* Fixed case-handling bugs in `RENAME` (i.e., channel rename) (#1456, thanks [@mogad0n](https://github.com/mogad0n)!)
* Fixed incorrect processing of color code escapes in MOTD files (#1467, thanks [@mogad0n](https://github.com/mogad0n)!)
* STS is no longer advertised to Tor clients (#1428, thanks [@Mikaela](https://github.com/Mikaela)!)
* Fixed HELP/HELPOP numerics not including the nick as an argument (#1472, thanks [@kylef](https://github.com/kylef)!)
* Made connection registration snomasks less confusing (#1396, thanks [@eskimo](https://github.com/eskimo)!)
* Fixed duplicated nicks in `KLINE` response (#1379, thanks [@mogad0n](https://github.com/mogad0n)!)
* The `RELAYMSG` tag name is now `draft/relaymsg`, conforming to the amended draft specification (#1468, thanks [@jlu5](https://github.com/jlu5)!)
* Fixed `SAJOIN` not sending a `MODE` line to the originating client (#1383, thanks [@mogad0n](https://github.com/mogad0n)!)
* Improved consistency of message sources sent by `CS AMODE` (#1383, thanks [@mogad0n](https://github.com/mogad0n)!)
* Fixed duplicated `JOIN` line sent to some clients using the `draft/resume-0.5` extension (#1397, thanks [@kylef](https://github.com/kylef)!)
* Added a warning that MySQL cannot be enabled by rehash (#1452, thanks [@Mikaela](https://github.com/Mikaela)!)

### Changed
* Channel-user modes (e.g., `+o`, `+v`) of always-on clients are now persisted in the database (#1345)
* `/CHANSERV PURGE` now takes `ADD`, `DEL`, and `LIST` subcommands; the separate `UNPURGE` command has been removed; `PURGE ADD` now requires a confirmation code (#1294, thanks [@mogad0n](https://github.com/mogad0n)!)
* The characters `<`, `>`, `'`, `"`, and `;` are no longer allowed in nicknames (previously registered account names containing these characters are still accepted) (#1436, thanks [@happyhater](https://github.com/happyhater)!)
* Authenticated clients from Tor now receive their (account-unique) always-on cloaked hostname; this allows channel operators to ban unauthenticated Tor users by banning `*!*@tor-network.onion` (#1479, thanks [@mogad0n](https://github.com/mogad0n)!)
* Included the network name in the human-readable final parameter of `001 RPL_WELCOME` (#1410)
* `RELAYMSG` can now take client-only tags (#1470)
* WebSocket listeners will attempt to negotiate the `text.ircv3.net` [subprotocol](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers#subprotocols); negotiating this is optional for clients (#1483)

### Added
* Added `UBAN`, a new command giving server operators a unified interface to D-LINEs (IP bans), K-LINEs (NUH mask bans, which are now deprecated), and account suspensions (`NS SUSPEND`) (#1447)
* Added `CHANSERV HOWTOBAN`, a ChanServ subcommand that helps channel operators choose an appropriate ban (#1447)
* Added a new channel mode `+f`; users who cannot join the channel due to `+i` or `+l` will be forwarded to the channel specified by `+f`. (#1260)
* Added support for the PROXY protocol v2 (#1389, thanks [@robinlemon](https://github.com/robinlemon)!)
* Added support for `/JOIN 0` (part all channels), requiring a confirmation code (#1417, thanks [@Mikaela](https://github.com/Mikaela)!)
* Added support for grouped nicknames as SASL usernames (#1476, thanks [@eskimo](https://github.com/eskimo)!)
* Added history support for `INVITE` (#1409, thanks [@Mikaela](https://github.com/Mikaela)!)
* Added a new channel setting accessible via `/CS SET`: `history-cutoff`, allowing the channel owner more fine-grained control over who can see history (#1490, thanks [@Mikaela](https://github.com/Mikaela)!)
* Added the `UTF8ONLY` ISUPPORT token, allowing the server to advertise to clients that only UTF-8 content is accepted (#1483)
* Added `/NICKSERV RENAME`, an operator-only command that can change the case of an account name (#1380, thanks [@LukeHoersten](https://github.com/LukeHoersten)!)

### Internal
* Added caching for serialized messages (#1387)
* Improved memory efficiency of line reading (#1231)

## [2.4.0] - 2020-11-08

We're pleased to announce Oragono 2.4.0, a new stable release.

This release includes a number of exciting enhancements and fixes. Here are some highlights:

* Support for migrating an Anope or Atheme database to Oragono (#1042)
* A pluggable system for validating external IPs, e.g., via DNSBLs (#68, thanks [@moortens](https://github.com/moortens)!)
* [draft/relaymsg](https://github.com/ircv3/ircv3-specifications/pull/417), a new draft extension simplifying bridging with other chat systems (thanks [@jlu5](https://github.com/jlu5)!)
* New moderation tools: `+u` ("auditorium", #1300), `+U` ("op-moderated", #1178), `+M` ("moderated-registered", #1182, thanks [@ajaspers](https://github.com/ajaspers)!), and `+b m:` (an extban for muting users, #307)

This release includes changes to the config file format, including one breaking change: `roleplay.enabled` now defaults to false (the new recommended default) instead of true when unset. Other config changes are backwards compatible and do not require updating the file before upgrading.

This release includes a database change. If you have `datastore.autoupgrade` set to `true` in your configuration, it will be automatically applied when you restart Oragono. Otherwise, you can update the database manually by running `oragono upgradedb` (see the manual for complete instructions).

Many thanks to [@ajaspers](https://github.com/ajaspers), [@jesopo](https://github.com/jesopo), [@moortens](https://github.com/moortens), and [@RunBarryRun](https://github.com/RunBarryRun) for contributing patches, to [@csmith](https://github.com/csmith) for contributing code reviews, to [@ajaspers](https://github.com/ajaspers), [@Amiga60077](https://github.com/Amiga60077), [@bogdomania](https://github.com/bogdomania), [@csmith](https://github.com/csmith), [@edk0](https://github.com/edk0), [@eskimo](https://github.com/eskimo), [@jlu5](https://github.com/jlu5), [@jwheare](https://github.com/jwheare), [@KoraggKnightWolf](https://github.com/KoraggKnightWolf), [@Mitaka8](https://github.com/Mitaka8), [@mogad0n](https://github.com/mogad0n), [@RyanSquared](https://github.com/RyanSquared), and [@vertisan](https://github.com/vertisan) for reporting issues and helping test, and to our translators for contributing translations.

### Config changes
* Added `server.ip-cloaking.enabled-for-always-on`, which generates a unique hostname for each always-on client. The recommended default value of this field is `true` (#1312)
* Added `server.coerce-ident`; if this is set to a string value, all user/ident fields supplied by clients are ignored and replaced with this value. The recommended default value of this field is `~u`. This simplifies bans. (#1340)
* Simplified the config file format for email verification into a new `accounts.nick-reservation.email-verification` section. The old format (`callbacks`) is still accepted (#1075)
* The recommended value of `roleplay.enabled` is now `false`; this field now defaults to false when unset (#1240, #1271)
* Added `server.relaymsg` section for configuring the new `draft/relaymsg` capability; added the new `relaymsg` operator capability for exercising it (#1119)
* Added `allow-environment-overrides` config variable, allowing config options to be overridden by environment variables. See the manual for more details. (#1049, thanks [@csmith](https://github.com/csmith)!)
* Added `server.ip-check-script` for configuring IP check plugins (#68, #1267, thanks [@moortens](https://github.com/moortens)!)
* Added `max-concurrency` restriction to `accounts.auth-script` section. The recommended default value is `64` (`0` or unset disable the restriction) (#1267)
* Added `accounts.registration.allow-before-connect`; this allows the use of the new `REGISTER` command before connecting to the server (#1075)
* Added `hidden` option in operator blocks: if set to `true`, operator status is hidden from commands like `WHOIS` that would otherwise display it (#1194)
* Added `accounts.nick-reservation.forbid-anonymous-nick-changes`, which forbids anonymous users from changing their nicknames after initially connecting (#1337, thanks [@Amiga60077](https://github.com/Amiga60077)!)
* Added `channels.invite-expiration`, allowing invites to `+i` channels to expire after a given amount of time (#1171)

### Security
* Added `/NICKSERV CLIENTS LOGOUT` command for disconnecting clients connected to a user account (#1072, #1272, thanks [@ajaspers](https://github.com/ajaspers)!)
* Disallowed the use of service nicknames during roleplaying (#1240, thanks [@Mitaka8](https://github.com/Mitaka8)!)
* Improved security properties of `INVITE` for invite-only channels, including an `UNINVITE` command (#1171)

### Removed
* Removed the request queue system for HostServ, i.e., the `REQUEST`, `APPROVE`, and `REJECT` subcommands of `HOSTSERV` (#1346)

### Fixed
* `PONG` is now sent with the server name as the first parameter, matching the behavior of other ircds (#1249, thanks [@jesopo](https://github.com/jesopo)!)
* It was not possible to set or unset the `+T` no-CTCP user mode; this has been fixed (#1299, thanks [@mogad0n](https://github.com/mogad0n)!)
* Fixed edge cases with `/NICKSERV SAREGISTER` of confusable nicknames (#1322, thanks [@mogad0n](https://github.com/mogad0n)!)
* Fixed websocket listeners with proxy-before-TLS enabled closing on invalid PROXY lines (#1269, thanks [@RyanSquared](https://github.com/RyanSquared)!)
* Fixed error responses and history for SANICK (#1277, #1278, thanks [@eskimo](https://github.com/eskimo)!)
* Ensured that stored realnames of always-on clients are deleted during account unregistration (#1330)
* Whitespace is now stripped from KLINEs (#1327, thanks [@mogad0n](https://github.com/mogad0n)!)
* Fixed incorrect `LUSERS` counts caused by KLINE (#1303, thanks [@mogad0n](https://github.com/mogad0n)!)
* `CHATHISTORY` queries for invalid channels now get an empty batch instead of a `FAIL` (#1322)
* `fakelag.messages-per-window = 0` no longer causes a panic (#861, thanks [@vertisan](https://github.com/vertisan)!)

### Added
* Added `oragono importdb` command for importing a converted Anope or Atheme database; see the manual for details (#1042)
* Added support for the new [draft/relaymsg](https://github.com/ircv3/ircv3-specifications/pull/417) extension, which simplifies bridging IRC with other protocols relaymsg (#1119, thanks [@jlu5](https://github.com/jlu5)!)
* Added `ip-check-script`, a scripting API for restricting access by client IP. We provide [oragono-dnsbl](https://github.com/oragono/oragono-dnsbl), an external script that can query DNSBLs for this purpose (#68, #1267, thanks [@moortens](https://github.com/moortens)!)
* Added channel mode `+u`. This is an "auditorium" mode that prevents unprivileged users from seeing each other's `JOIN` and `PART` lines. It's useful for large public-announcement channels, possibly in conjunction with `+m` (#1300)
* Added channel mode `+U`. This is an "op-moderated" mode; messages from unprivileged users are sent only to channel operators, who can then choose to grant them `+v`. (#1178)
* Added a mute extban `+b m:`: users matching the ban expression (e.g., `+b m:*!*@j6dwi4vacx47y.irc`) will be able to join the channel, but will be unable to speak. (#307)
* Added support for the new [draft/register](https://gist.github.com/edk0/bf3b50fc219fd1bed1aa15d98bfb6495) extension, which exposes a cleaner account registration API to clients (#1075, thanks [@edk0](https://github.com/edk0)!)
* Added a `379 RPL_WHOISMODES` line to the `WHOIS` response, making it easier for operators to see other users' modes (#769, thanks [@Amiga60077](https://github.com/Amiga60077) and [@KoraggKnightWolf](https://github.com/KoraggKnightWolf)!)
* Added `/CHANSERV DEOP` command for removing channel operator privileges (#361, thanks [@RunBarryRun](https://github.com/RunBarryRun)!)
* Added `r` flag to `/WHO` responses for registered nicknames (#1366, thanks [@Amiga60077](https://github.com/Amiga60077)!)

### Changed
* Always-on clients now receive a user/ident of `~u` by default, instead of `~user`; this can be changed by setting the `coerce-ident` field (#1340)
* `/NICKSERV SUSPEND` has been modified to take subcommands (`ADD`, `DEL`, and `LIST`); the `ADD` subcommand now accepts time duration and reason arguments. See `/msg NickServ HELP SUSPEND` for details. (#1274, thanks [@mogad0n](https://github.com/mogad0n)!)
* Only the channel founder can kick the channel founder, regardless of either party's modes (#1262)
* `/NICKSERV SESSIONS` is now `/NICKSERV CLIENTS LIST`, but the old command is still accepted (#1272, thanks [@ajaspers](https://github.com/ajaspers)!)
* Improved `SETNAME` behavior for legacy clients (#1358, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf)!)
* Halfops can set the channel topic (#1306)
* Full client certificates are now passed to auth scripts. This allows for more flexible checks on certificates, including verification against an internal CA (#414)

### Internal
* Added a logline for debugging client disconnections (#1293)
* Renamed `conventional.yaml` to `traditional.yaml` (#1350)
* Integration tests are now run during CI (#1279)


## [2.3.0] - 2020-09-06

We're pleased to announce Oragono 2.3.0, a new stable release.

This release contains primarily bug fixes, but includes one notable feature enhancement: a change contributed by [@hhirtz](https://github.com/hhirtz) that updates the `draft/rename` specification to correspond to the new (soon-to-be) published draft.

Many thanks to [@hhirtz](https://github.com/hhirtz) for contributing patches, to [@bogdomania](https://github.com/bogdomania), [@digitalcircuit](https://github.com/digitalcircuit), [@ivan-avalos](https://github.com/ivan-avalos), [@jesopo](https://github.com/jesopo), [@kylef](https://github.com/kylef), [@Mitaka8](https://github.com/Mitaka8), [@mogad0n](https://github.com/mogad0n), and [@ProgVal](https://github.com/ProgVal) for reporting issues and helping test, and to our translators for contributing translations.

This release includes no changes to the config file format or database changes.

### Config changes
* The recommended value of `lookup-hostnames` for configurations that cloak IPs (as has been the default since 2.1.0) is now `false` (#1228)

### Security
* Mitigated a potential DoS attack on websocket listeners (#1226)

### Removed
* Removed `/HOSTSERV OFFERLIST` and related commands; this functionality is superseded by IP cloaking (#1190)

### Fixed
* Fixed an edge case in handling no-op nick changes (#1242)
* Fixed edge cases with users transitioning in and out of always-on status (#1218, #1219, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed a race condition related to the registration timeout (#1225, thanks [@hhirtz](https://github.com/hhirtz)!)
* Fixed incorrectly formatted account tags on some messages (#1254, thanks [@digitalcircuit](https://github.com/digitalcircuit)!)
* Improved checks for invalid config files (#1244, thanks [@ivan-avalos](https://github.com/ivan-avalos)!)
* Fixed messages to services and `*playback` not receiving echo-message when applicable (#1204, thanks [@kylef](https://github.com/kylef)!)
* Fixed a help string (#1237, thanks [@Mitaka8](https://github.com/Mitaka8)!)

### Changed
* Updated `draft/rename` implementation to the latest draft (#1223, thanks [@hhirtz](https://github.com/hhirtz)!)

### Internal
* Official release builds now use Go 1.15 (#1195)
* `/INFO` now includes the Go version (#1234)

## [2.2.0] - 2020-07-26

We're pleased to announce Oragono 2.2.0, a new stable release.

This release contains several notable enhancements, as well as bug fixes:

* Support for tracking seen/missed messages across multiple devices (#843)
* WHOX support contributed by @jesopo (#938)
* Authentication of users via external scripts (#1107)

Many thanks to [@clukawski](https://github.com/clukawski) and [@jesopo](https://github.com/jesopo) for contributing patches, to [@ajaspers](https://github.com/ajaspers), [@bogdomania](https://github.com/bogdomania), [@csmith](https://github.com/csmith), [@daurnimator](https://github.com/daurnimator), [@emersonveenstra](https://github.com/emersonveenstra), [@eskil](https://github.com/eskil), [@eskimo](https://github.com/eskimo), Geo-, [@happyhater](https://github.com/happyhater), [@jesopo](https://github.com/jesopo), [@jwheare](https://github.com/jwheare), [@k4bek4be](https://github.com/k4bek4be), [@KoraggKnightWolf](https://github.com/KoraggKnightWolf), [@kylef](https://github.com/kylef), [@LukeHoersten](https://github.com/LukeHoersten), [@mogad0n](https://github.com/mogad0n), r3m, [@RyanSquared](https://github.com/RyanSquared), savoyard, and [@wrmsr](https://github.com/wrmsr) for reporting issues and helping test, and to our translators for contributing translations.

This release includes changes to the config file format, including one breaking change: `timeout` is no longer an acceptable value of `accounts.nick-reservation.method`. (If you were using it, we suggest `strict` as a replacement.) All other changes to the config file format are backwards compatible and do not require updating before restart.

This release includes a database change. If you have `datastore.autoupgrade` set to `true` in your configuration, it will be automatically applied when you restart Oragono. Otherwise, you can update the database manually by running `oragono upgradedb` (see the manual for complete instructions).

### Removed
* Timeout-based nickname enforcement has been removed. We recommend `strict` as the default enforcement method. Users who configured `timeout` for their account will be upgraded to `strict`. With `accounts.login-via-pass-command` enabled, clients lacking support for SASL can authenticate via the `PASS` (server password command) by sending `account_name:account_password` as the server password. (#1027)
* Native support for LDAP has been removed. LDAP is now supported via the external [oragono-ldap](https://github.com/oragono/oragono-ldap) plugin; see its repository page for details. (#1142, #1107)

### Config changes
* Added `server.enforce-utf8`, controlling whether the server enforces that messages be valid UTF-8; a value of `true` for this is now the recommended default (#1151)
* Added `history.tagmsg-storage` for configuring which TAGMSG are stored in history; if this is not configured, TAGMSG will not be stored (#1172)
* All TLS certificate fingerprints in the config file are now named `certfp` instead of `fingerprint` (the old name of `fingerprint` is still accepted) (#1050, thanks [@RyanSquared](https://github.com/RyanSquared)!)
* Added `accounts.auth-script` section for configuring external authentication scripts (#1107, thanks [@daurnimator](https://github.com/daurnimator)!)
* Removed `accounts.ldap` section for configuring LDAP; LDAP is now available via the auth-script plugin interface (#1142)
* Added `defcon` operator capability, allowing use of the new `/DEFCON` command (#328)
* Default `awaylen`, `kicklen`, and `topiclen` limits now reflect the 512-character line limit (#1112, thanks [@k4bek4be](https://github.com/k4bek4be)!)
* Added `extjwt` section for configuring the EXTJWT extension (#948, #1136)
* `login-via-pass-command: true` is now a recommended default (#1186)

### Added
* Added support for [WHOX](https://github.com/ircv3/ircv3-specifications/issues/81), contributed by [@jesopo](https://github.com/jesopo) (#938, thanks!)
* Added support for tracking missed messages across multiple devices; see the "history" section of the manual for details (#843, thanks [@jwheare](https://github.com/jwheare) and [@wrmsr](https://github.com/wrmsr)!)
* Added `/NICKSERV SUSPEND` and `/NICKSERV UNSUSPEND` commands, allowing operators to suspend access to an abusive user account (#1135)
* Added support for external authentication systems, via subprocess ("auth-script") invocation (#1107, thanks [@daurnimator](https://github.com/daurnimator)!)
* Added the `/DEFCON` command, allowing operators to respond to spam or DoS attacks by disabling features at runtime without a rehash. (This feature requires that the operator have a newly defined capability, named `defcon`; this can be added to the appropriate oper blocks in the config file.) (#328, thanks [@bogdomania](https://github.com/bogdomania)!)
* Added support for the [EXTJWT](https://github.com/ircv3/ircv3-specifications/pull/341) draft extension, allowing Oragono to be integrated with other systems like Jitsi (#948, #1136)
* Services (NickServ, ChanServ, etc.) now respond to CTCP VERSION messages (#1055, thanks [@jesopo](https://github.com/jesopo)!)
* Added `BOT` ISUPPORT token, plus a `B` flag for bots in `352 RPL_WHOREPLY` (#1117)
* Added support for the `+T` no-CTCP user mode (#1007, thanks [@clukawski](https://github.com/clukawski)!)
* Added support for persisting the realname of always-on clients (#1065, thanks [@clukawski](https://github.com/clukawski)!)
* Added a warning on incorrect arguments to `/NICKSERV REGISTER` (#1179, thanks [@LukeHoersten](https://github.com/LukeHoersten)!)
* `/NICKSERV SET PASSWORD` now sends a warning (#1208)

### Fixed
* Fixed channels with only invisible users not being displayed in `/LIST` output (#1161, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed `INVITE` not overriding a `+b` ban (#1168)
* Fixed incorrect `CHGHOST` lines during authentication with `/NICKSERV IDENTIFY` under some circumstances (#1108, thanks Geo-!)
* Fixed incorrect `CHGHOST` lines sent to users during connection registration (#1125, thanks [@jesopo](https://github.com/jesopo)!)
* Fixed a number of issues affecting the `znc.in/playback` capability, in particular restoring compatibility with Palaver (#1205, thanks [@kylef](https://github.com/kylef)!)
* Fixed interaction of auto-away with the regular `/AWAY` command (#1207)
* Fixed an incorrect interaction between always-on and `/NS SAREGISTER` (#1216)
* Fixed a race condition where nicknames of signed-out users could remain in the channel names list (#1166, thanks [@eskimo](https://github.com/eskimo)!)
* Fixed the last line of the MOTD being truncated in the absence of a terminating `\n` (#1167, thanks [@eskimo](https://github.com/eskimo)!)
* Fixed `away-notify` lines not being sent on channel JOIN (#1198, thanks savoyard!)
* Fixed incorrect source of some nickserv messages (#1185)
* Fixed idle time being updated on non-PRIVMSG commands (thanks r3m and [@happyhater](https://github.com/happyhater)!)
* Fixed `/NICKSERV UNREGISTER` and `/NICKSERV ERASE` not deleting stored user modes (#1157)

### Security
* Connections to an STS-only listener no longer reveal the exact server version or server creation time (#802, thanks [@csmith](https://github.com/csmith)!)

### Changed
* `/DLINE` now operates on individual client connections (#1135)
* When using the multiclient feature, each client now has its own independent `MONITOR` list (#1053, thanks [@ajaspers](https://github.com/ajaspers)!)
* `MONITOR L` now lists the nicknames in the form they were originally sent with `MONITOR +`, without casefolding (#1083)
* We now send the traditional `445 ERR_SUMMONDISABLED` and `446 ERR_USERSDISABLED` in response to the `SUMMON` and `USERS` commands (#1078, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf)!)
* RPL_ISUPPORT parameters with no values are now sent without an `=` (#1067, #1069, #1091, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf) and [@jesopo](https;//github.com/jesopo)!)
* TAGMSG storage is now controlled via the `history.tagmsg-storage` config block (#1172)
* `/NICKSERV CERT ADD` with no argument now adds the user's current TLS certificate fingerprint, when applicable (#1059, thanks [@emersonveenstra](https://github.com/emersonveenstra)!)

### Internal
* The config file containing recommended defaults is now named `default.yaml`, instead of `oragono.yaml` (#1130, thanks [@k4bek4be](https://github.com/k4bek4be)!)
* The output of the `/INFO` command now includes the full git hash, when applicable (#1105)

## [2.1.0] - 2020-06-01
We're pleased to announce Oragono 2.1.0, a new stable release.

Since the release of 2.0.0 in March, a number of new communities and organizations have adopted Oragono as a communications tool. This new release incorporates many improvements and fixes derived from the experiences of real-world operators and end users. Highlights include:

* Native support for websockets contributed by [@hhirtz](https://github.com/hhirtz), eliminating the need for a separate websockets-to-IRC proxy server
* Tighter control over the relationship between account names and nicknames, eliminating the need for extbans
* Support for sending account verification emails directly from Oragono, including DKIM signatures

Many thanks to [@ajaspers](https://github.com/ajaspers) and [@hhirtz](https://github.com/hhirtz) for contributing patches, to [@ajaspers](https://github.com/ajaspers), [@eklitzke](https://github.com/eklitzke), and [@hhirtz](https://github.com/hhirtz) for contributing code reviews, to [@ajaspers](https://github.com/ajaspers), [@bogdomania](https://github.com/bogdomania), [@clukawski](https://github.com/clukawski), Csibesz, [@csmith](https://github.com/csmith), [@eklitzke](https://github.com/eklitzke), [@nxths](https://github.com/nxths), [@hhirtz](https://github.com/hhirtz), [@jesopo](https://github.com/jesopo), [@jlnt](https://github.com/jlnt), [@justjanne](https://github.com/justjanne), [@jwheare](https://github.com/jwheare), [@k4bek4be](https://github.com/k4bek4be), [@KoraggKnightWolf](https://github.com/KoraggKnightWolf), [@kula](https://github.com/kula), [@kylef](https://github.com/kylef), [@Mitaka8](https://github.com/Mitaka8), [@petteri](https://github.com/petteri), [@PizzaLover2007](https://github.com/PizzaLover2007), [@prawnsalad](https://github.com/prawnsalad), [@RyanSquared](https://github.com/RyanSquared), savoyard, and [@xPaw](https://github.com/xPaw) for reporting issues, and to [@bogdomania](https://github.com/bogdomania), [@boppy](https://github.com/boppy), Nuve, stickytoffeepuddingwithcaramel, and [@vegax87](https://github.com/vegax87) for contributing translations.

This release includes changes to the config file format, including one breaking change: support for `server.ip-cloaking.secret-environment-variable` has been removed. (See below for instructions on how to upgrade if you were using this feature.) All other changes to the config file format are backwards compatible and do not require updating before restart.

This release includes a database change. If you have `datastore.autoupgrade` set to `true` in your configuration, it will be automatically applied when you restart Oragono. Otherwise, you can update the database manually by running `oragono upgradedb` (see the manual for complete instructions).

This release includes a change to the MySQL schema. This change will be applied automatically when you restart Oragono. It is fully backwards compatible (i.e., if it is necessary for you to downgrade Oragono back to 2.0.0, it will not be necessary to downgrade the schema).

### Config Changes
* Added `websocket` attribute of individual listeners, and a new `server.websockets` section, for configuring websocket listeners. (#967, thanks [@hhirtz](https://github.com/hhirtz)!)
* The recommended default is now to enable IP cloaking. In order to facilitate this, the cloaking secret is now stored in the database, instead of the config file. If you currently have a secret stored in the config file (as `server.ip-cloaking.secret`), it will be automatically imported into the database. If you were using `secret-environment-variable` to distribute your cloaking secret, you can import it manually after restart using the new `/HOSTSERV SETCLOAKSECRET` command. (#952)
* Added `accounts.nick-reservation.force-nick-equals-account`, which ensures that logged-in clients are using their account name as their nickname. This eliminates the need for extbans and is a new recommended default. (#864)
* Added `guest-nickname-format` and `force-guest-format`, which optionally add a prefix like `Guest-` to the nicknames of unauthenticated users (#749)
* The recommended default is now to enable history storage and playback, with messages expiring after 7 days. (As with all changes in recommended config values, applying this to an existing config file requires explicitly changing the values.) (#1030)
* Added `history.retention` section for controlling new features related to history storage and deletion (#858)
* The recommended default for `accounts.multiclient.always-on` is now `opt-in` (#919)
* Added `accounts.default-user-modes`; the recommended default is now to set `+i` on all users automatically (#942, thanks [@ajaspers](https://github.com/ajaspers)!)
* Added `channels.list-delay`, allowing restrictions on channel listings as a defence against spambots (#964)
* Added `accounts.multiclient.auto-away`, allowing always-on clients to be automatically marked as away when all their sessions disconnect
* Added `accounts.throttling` as a global throttle on the creation of new accounts (#913)
* New format for `accounts.callbacks.mailto`, allowing direct email sending and DKIM signing (#921)
* Added `accounts.login-via-pass-command`, providing a new mechanism for legacy clients to authenticate to accounts by sending `PASS account:password` pre-registration (#1020)
* Added `datastore.mysql.socket-path`, allowing MySQL connections over UNIX domain sockets (#1016, thanks savoyard and [@ajaspers](https://github.com/ajaspers)!)
* Added `roleplay` section for controlling the server's roleplay features (#865)
* The recommended default for `accounts.nick-reservation.allow-custom-enforcement` is now `false` (#918)
* The recommended default is now to allow PROXY and WEBIRC lines from localhost (#989, #1011)
* Added `channels.registration.operator-only`, optionally restricting channel registrations to operators (#685)
* Added `server.output-path` for controlling where the server writes output files (#1004)
* Operator capability names prefixed with `oper:` have been normalized to remove the prefix (the old names are still respected in the config file) (#868)
* The log category names `localconnect` and `localconnect-ip` have been changed to `connect` and `connect-ip` respectively (the old names are still respected in the config file) (#940)

### Security
* Fixed incorrect enforcement of ban/invite/exception masks under some circumstances (#983)
* STATUSMSG were being stored in history without the relevant minimum-prefix information, so they could be replayed to unprivileged users. This was fixed by not storing them at all. (#959, thanks [@prawnsalad](https://github.com/prawnsalad)!)
* Fixed invisible users not being hidden from `WHO *` queries (#991, thanks [@ajaspers](https://github.com/ajaspers)!)
* Restricted nicknames of some additional common services: `OperServ`, `BotServ`, `MemoServ`, and `Global` (#1080, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf)!)

### Fixed
* Fixed incorrect rejection of `draft/multiline` messages containing blank lines (#1005, thanks [@jwheare](https://github.com/jwheare)!)
* Fixed roleplay commands, which were completely broken from v1.1.0 through v2.0.0 (#865, thanks [@petteri](https://github.com/petteri) and [@Mitaka8](https://github.com/Mitaka8)!)
* Fixed `/SAMODE` applying user mode changes to the operator instead of the target user (#866, thanks [@csmith](https://github.com/csmith)!)
* Fixed some channels not being unregistered during account unregistration (#889)
* Fixed `/NICKSERV SET` and related commands being unavailable when account registration is disabled (#922, thanks [@PizzaLover2007](https://github.com/PizzaLover2007)!)
* Fixed `TAGMSG` not being replayed correctly in history (#1044)
* Fixed incorrect `401 ERR_NOSUCHNICK` responses on `TAGMSG` sent to a service (#1051, thanks [@ajaspers](https://github.com/ajaspers)!)
* Fixed `301 RPL_AWAY` not being sent in `WHOIS` responses when applicable (#850)
* `/OPER` with no password no longer disconnects the client (#951)
* Fixed failure to send extended-join responses after account unregistration (#933, thanks [@jesopo](https://github.com/jesopo)!)
* Improved validation of channel keys (#1021, thanks [@kylef](https://github.com/kylef)!)
* Fixed labeling of `421 ERR_UNKNOWNCOMMAND` responses (#994, thanks [@k4bek4be](https://github.com/k4bek4be)!)
* Fixed incorrect parsing of ident protocol responses (#1002, thanks [@justjanne](https://github.com/justjanne)!)
* Fixed registration completing after `NICK` and an ident response, without waiting for `USER` (#1057, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf)!)
* Fixed messages rejected by the `+R` mode being stored in history (#1061, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf)!)
* Fixed redundant `/INVITE` commands not sending `443 ERR_USERONCHANNEL` (#842, thanks [@hhirtz](https://github.com/hhirtz)!)
* Fixed `/NICKSERV REGISTER` response displaying `mailto:` out of context (#985, thanks [@eklitzke](https://github.com/eklitzke)!)
* Fixed nickname changes not sending `731 RPL_MONOFFLINE` when appropriate (#1076, thanks [@ajaspers](https://github.com/ajaspers)!)
* Fixed incorrect MONITOR responses in some cases (#1086, thanks [@ajaspers](https://github.com/ajaspers)!)
* Fixed HostServ approval and rejection notices being sent from the wrong source (#805)
* Error messages for invalid TLS certificate/key pairs are now more informative (#982)
* Fixed error message when attempting to attach a plaintext session to an always-on client (#955, thanks [@bogdomania](https://github.com/bogdomania) and [@xPaw](https://github.com/xPaw)!)
* Increased the TLS handshake timeout, increasing reliability under high CPU contention (#894)
* Fixed `CHANMODES` ISUPPORT token (#408, #874, thanks [@hhirtz](https://github.com/hhirtz)!)
* Fixed `002 RPL_MYINFO` parameters (#1058, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf)!)
* Fixed incorrect parameter limit for `MONITOR` in the `TARGMAX` isupport token (#1090, thanks [@KoraggKnightWolf](https://github.com/KoraggKnightWolf)!)
* Fixed edge cases in handling of the `+k` channel mode parameter (#874, thanks [@hhirtz](https://github.com/hhirtz)!)
* `account-notify` lines are now part of the labeled-response batch when applicable (#1018)
* Fixed incorrect help description of channel mode `+R` (#930, thanks [@PizzaLover2007](https://github.com/PizzaLover2007)!)
* Fixed `255 RPL_LUSERME` response to indicate that the number of federated peer servers is 0 (#846, thanks [@RyanSquared](https://github.com/RyanSquared)!)

### Changed
* Account names are now permanent identifiers; they cannot be re-registered after unregistration, and applicable nickname protections remain in force. (#793)
* User modes of always-on clients now persist across server restarts (#819)
* Registered channels with no members remain present on the server, including their in-memory history messages when applicable (#704, thanks [@bogdomania](https://github.com/bogdomania)!)
* Updated the [setname](https://ircv3.net/specs/extensions/setname) IRCv3 capability to its ratified version (#1001)
* `/CHANSERV AMODE` now takes immediate effect (#729)
* The channel founder can now take any action that would require channel privileges without actually having the `+q` mode (#950, #998)
* Account unregistration now always disconnects the client (#1028)
* Fakelag is now temporarily disabled during the sending of a `draft/multiline` message batch (#817)
* Failed attempts to join a `+R` channel now send `477 ERR_NEEDREGGEDNICK` (#936, thanks [@PizzaLover2007](https://github.com/PizzaLover2007), [@jesopo](https://github.com/jesopo)!)
* `353 RPL_NAMREPLY` now always uses a trailing parameter, for compatibility with incorrect client implementations (#854, #862)
* Channels with persistent history can no longer be renamed with `/RENAME` (#827)
* The self-signed certificate generation command `oragono mkcerts` now generates a 2048-bit RSA certificate, instead of a NIST P-521 ECDSA certificate (#898)
* Cleaned up compatibility with an obsolete WEBIRC escaping convention (#869)
* The cloak secret is now stored in the database, so it can no longer be rotated by changing `server.ip-cloaking.secret`. To rotate the secret, use the new `/HOSTSERV SETCLOAKSECRET` command. (#952)

### Added
* Added native support for websockets (#967, thanks [@hhirtz](https://github.com/hhirtz)!)
* Added support for sending verification emails directly (i.e., without a MTA/smarthost), including DKIM signing (#920, #921)
* Added `/NICKSERV LIST` and `/CHANSERV LIST`, allowing operators to list registered nicknames and channels (#974, thanks [@ajaspers](https://github.com/ajaspers)!)
* Added auto-away feature for marking always-on clients away when all their sessions are disconnected; see `accounts.multiclient.auto-away` and `/NICKSERV HELP SET` for more information (#824)
* Added `/HISTSERV PLAY`, which plays back history messages as NOTICEs from the `HistServ` service (#383, thanks [@nxths](https://github.com/nxths)!)
* Added `/HISTSERV DELETE` for deleting history messages (see the config option `history.retention.allow-individual-delete`) (#858)
* Added `/HISTSERV FORGET` for deleting all history messages associated with an account (see the config option `history.retention.enable-account-indexing`) (#858)
* Added `/HISTSERV EXPORT` for exporting all history messages associated with an account as JSON. This can be used at the user's request for regulatory compliance reasons (see the config option `history.retention.enable-account-indexing`) (#858)
* Added support for logging legacy clients into accounts via the `PASS` command, with the [account:password](https://freenode.net/kb/answer/registration#logging-in) syntax used by Freenode. To enable this feature, set `accounts.login-via-pass-command` to `true`. (#1020, thanks [@jlnt](https://github.com/jlnt)!)
* Added `/NICKSERV ERASE` as an escape hatch for operators, allowing an account to be erased and re-registered (#793)
* Added support for playing back `MODE` and `TOPIC` messages in history (#532)
* Added `conventional.yaml`, a version of the config file that provides a more traditional IRC experience. We recommend a config file based on `oragono.yaml` for production networks, and one based on `conventional.yaml` for IRCv3 conformance testing. (#918)
* Added an optional global throttle on the creation of new accounts (#913)
* Added support for restricting `/LIST` responses sent to anonymous clients (#964)
* Added support for the Plan 9 operating system and its derivatives, including testing on 9front (#1025, thanks [@clukawski](https://github.com/clukawski)!)

### Removed
* Removed support for colored log output (#940, #939)
* Removed support for distributing the cloaking secret via environment variables (#952)

### Internal
* `make build` now includes an abbreviated git hash in the `002 RPL_YOURHOST` and `004 RPL_MYINFO` version strings, when applicable (#1031)
* Official releases no longer contain the git hash, only the revision tag (#1031)
* Official releases are now built with `-trimpath` (#901)

## [2.0.0] - 2020-03-08
We're pleased to announce Oragono 2.0.0, a major update with a wide range of enhancements and fixes. Highlights include:

* Support for storing chat history in a MySQL backend
* Full "bouncer" functionality, including "always-on" clients that remain present on the server even when disconnected
* LDAP support contributed by [@mattouille](https://github.com/mattouille)
* Support for the ratified [labeled-response](https://ircv3.net/specs/extensions/labeled-response.html) IRCv3 capability
* Enhanced support for Kubernetes
* Many new service commands, improving management of client certificates, vhosts, and channel ownership

Many thanks to [@csmith](https://github.com/csmith), [@mattouille](https://github.com/mattouille), and [@xPaw](https://github.com/xPaw) for contributing patches, to [@csmith](https://github.com/csmith) and [@wrmsr](https://github.com/wrmsr) for contributing code reviews, to [@bogdomania](https://github.com/bogdomania), [@brenns10](https://github.com/brenns10), [@daurnimator](https://github.com/daurnimator), [@ekianjo](https://github.com/ekianjo), horseface, [@ivucica](https://github.com/ivucica), [@jesopo](https://github.com/jesopo), [@jwheare](https://github.com/jwheare), KoDi, lover, [@notbandali](https://github.com/notbandali), [@poVoq](https://github.com/poVoq), [@TETYYS](https://github.com/TETYYS), and [@zaher](https://github.com/zaher) for reporting issues, and to [@bogdomania](https://github.com/bogdomania) and Nuve for contributing translations.

This release includes changes to the config file format, including two breaking changes:

1. Backwards compatibility with the old `server.listen` format for configuring listeners has been removed; you must now use the `server.listeners` format that was introduced in 1.2.0.
2. The two sections `server.connection-limits` and `server.connection-throttling` have been consolidated into one new section, `server.ip-limits`.

Other changes to the config file format are backwards compatible and do not require updating before restart. To minimize potential downtime, we suggest the following workflow:

1. Without upgrading your `oragono` binary, edit your config file to add new `server.listeners` and `server.ip-limits` sections, based on the example config file
2. Rehash your server, confirming that the new config file is valid for for the previous version of the server
3. Upgrade your `oragono` binary to the new 2.0.x version and restart your server
4. Once your deployment is stable on 2.0.x, delete the old `server.listen`, `server.connection-limits`, and `server.connection-throttling` sections from your config, and rehash your server to confirm

This release includes a database change. If you have `datastore.autoupgrade` set to `true` in your configuration, it will be automatically applied when you restart Oragono. Otherwise, you can update the database manually by running `oragono upgradedb` (see the manual for complete instructions).

### Config Changes
* Desupported `server.listen` in favor of `server.listeners`, a breaking change (#794)
* Desupported `server.connection-limits` and `server.connection-throttling` in favor of `server.ip-limits`, a breaking change (#646)
* The recommended default is now to allow plaintext only on loopback interfaces (#801)
* Added `server.casemapping` option to control which Unicode nicknames and channels are allowed (#693)
* Added `server.lookup-hostnames` and `server.forward-confirm-hostnames` options to control hostname lookup (#688)
* Added new `limits.multiline` section to control the new `draft/multiline` capability
* Added sections for enabling the optional MySQL history storage backend: `datastore.mysql` for connecting to the server and `history.persistent` for controlling which messages are stored
* Added `history.restrictions` for preventing people from retrieving arbitrarily old history messages
* Added `history.znc-maxmessages`, allowing a higher history replay limit for bouncer emulation relative to CHATHISTORY
* Added `accounts.vhosts.offer-list`, allowing users to take pre-approved vhosts without operator approval (#737)
* Renamed `accounts.bouncer` to `accounts.multiclient` (the old name still works) (#787)
* New recommended values of `server.max-sendq`, `server.ip-cloaking.num-bits`, `accounts.registration.bcrypt-cost`, `accounts.nick-reservation.enabled` (now true), `accounts.multiclient.allowed-by-default` (now true)
* Added `server.ip-cloaking.secret-environment-variable`, allowing the cloaking secret to be deployed via an environment variable for use in Kubernetes (#741, thanks [@daurnimator](https://github.com/daurnimator)!)

### Security
* Added forward confirmation of reverse DNS lookups for hostnames: to enable this, set `server.forward-confirm-hostnames` to true (#688)
* Added protection against confusable channel names (#581)
* Fixed cases where Tor users could receive CTCP messages, contrary to expectations (#752, #753)
* Fixed `NS INFO` displaying the local timezone (#710)
* Fixed `accounts.authentication-enabled` failing to disable the `NS IDENTIFY` command (#721)

### Added
* Added support for persistent history storage in MySQL (#348)
* Added support for "always-on" clients that remain present on the server even when disconnected (#348, #701)
* Added support for LDAP (#690, thanks [@mattouille](https://github.com/mattouille), [@ivucica](https://github.com/ivucica), and [@mabgnu](https://github.com/mabgnu)!)
* Added support for the new [draft/multiline](https://github.com/ircv3/ircv3-specifications/pull/398) specification (#670, thanks [@jwheare](https://github.com/jwheare) and [@jesopo](https://github.com/jesopo)!)
* Added new modes for Unicode characters in nicknames and channel names: ASCII-only and "permissive" (allowing emoji) (#693)
* Added support for plaintext PROXY lines ahead of a TLS handshake, improving compatibility with some Kubernetes load balancers (#561, thanks [@RyanSquared](https://github.com/RyanSquared) and [@daurnimator](https://github.com/daurnimator)!)
* Added support for authenticating operators by TLS client certificates, and automatically applying operator privileges on login (#696, thanks [@RyanSquared](https://github.com/RyanSquared)!)
* Added `/DEOPER` command to remove operator privileges (#549, thanks [@bogdomania](https://github.com/bogdomania)!)
* Added `/CHANSERV TRANSFER`, allowing transfers of channel ownership (#684)
* Added `/NICKSERV CERT`, allowing users to manage their authorized client certificates (#530)
* Added `/HOSTSERV TAKE`, allowing users to take pre-approved vhosts without operator approval (#737)
* Added support for configuring connection limits and throttling for individual CIDRs (#646, thanks KoDi!)
* Added `/CHANSERV PURGE`, allowing server administrators to shut down channels (#683)
* Added `/CHANSERV CLEAR`, allowing channel founders to reset stored bans and privileges (#692)
* Added `/CHANSERV SET`, allowing channel founders to disable channel history (#379)
* Added account preference `AUTOREPLAY-JOINS`, allowing greater control over when joins and parts appear in history replay (#616, thanks [@zaher](https://github.com/zaher)!)
* Added `/DEBUG CRASHSERVER` command (#791)
* `znc.in/playback` now supports nicknames as targets (#830)
* Added channel mode `+C` to suppress CTCP messages to a channel (#756)
* Added some missing snomasks for events related to accounts and vhosts (`+s v` to enable vhost snomasks) (#347, #103)

### Changed
* Updated CHATHISTORY support to the [latest draft](https://github.com/ircv3/ircv3-specifications/pull/393) (#621, thanks [@prawnsalad](https://github.com/prawnsalad)!)
* Updated to the ratified [labeled-response](https://ircv3.net/specs/extensions/labeled-response.html) specification from the earlier `draft/labeled-response-0.2` (#757)
* `/HISTORY` now defaults to returning 100 messages, and also takes time durations like `1h` as arguments (#621, thanks lover!)
* D-Lines are no longer enforced against loopback IPs (#671)
* Password length limit was reduced from 600 bytes to 300 bytes (#775)

### Fixed
* Fixed a bug where `znc.in/playback` commands would play every channel, regardless of the target parameter (#760, thanks [@brenns10](https://github.com/brenns10)!)
* Fixed `MODE -o` not removing all operator permissions (#725, #549, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed client-only tags being relayed in direct messages to users without the `message-tags` capability (#754, thanks [@jesopo](https://github.com/jesopo)!)
* Fixed the channel user limit (the `+l` mode) not persisting after server restart (#705, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed response to `JOIN` lines with parameters ending in a comma (#679, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed confusable protection not being removed from unregistered accounts (#745, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed rehash not enabling nickname reservation, vhosts, or history under some circumstances (#702, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed responses to the `USERHOST` command (#682)
* Fixed bad results when running `oragono upgradedb` against a missing database file (#715, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed confusing `NS GHOST` behavior when nickname reservation is disabled (#727, thanks horseface!)
* Fixed validation of authzid during SASL (#716, thanks [@xPaw](https://github.com/xPaw)!)
* Non-ASCII characters are proactively disallowed in `ip-cloaking.netname` (#713, thanks [@bogdomania](https://github.com/bogdomania)!)
* Limited the time during which `znc.in/playback` affects channel joins (#829)

### Removed
* Removed `oragono.io/maxline-2` capability in favor of the new `draft/multiline` capability (#670, #752)
* Removed `oragono.io/bnc` capability (multiclient functionality is now controllable only via server config and `/NS SET MULTICLIENT`) (#787)
* Removed `draft/acc` capability and related `ACC` command (#723)

### Internal Notes
* Updated to Go 1.14 and modules, simplifying the build process (#699)

## [1.2.0] - 2019-11-17
We're pleased to announce Oragono 1.2.0. This version contains bug fixes and minor improvements.

Many thanks to [@bogdomania](https://github.com/bogdomania), [@csmith](https://github.com/csmith), [@edmund-huber](https://github.com/edmund-huber), [@jesopo](https://github.com/jesopo), [@jwheare](https://github.com/jwheare), [@poVoq](https://github.com/oragono/oragono/issues/624), [@prawnsalad](https://github.com/prawnsalad), and stealthgin for reporting issues and contributing code reviews, and also to [@bogdomania](https://github.com/bogdomania), Forbidden (cptbl00dra1n), Nuve, [@streaps](https://github.com/streaps), and UnLokitoFeliz for contributing translations.

This release includes a change to the config file format: the old `server.listen` format for configuring listeners has been replaced by a new `server.listeners` format. See the bundled `oragono.yaml` configuration file for a commented example. For now, Oragono maintains backwards compatibility with the old format. To minimize potential downtime, we recommend the following workflow:

1. Without rewriting your config file, upgrade your `oragono` binary to the new 1.2.x version and restart your server
2. Rewrite your configuration file to use the new `server.listeners` format
3. Rehash your server, confirming that the rewritten config file is valid and correct

This release includes a database change. If you have `datastore.autoupgrade` set to `true` in your configuration, it will be automatically applied when you restart Oragono. Otherwise, you can update the database manually by running `oragono upgradedb` (see the manual for complete instructions).

### Config Changes
* Replaced `server.listen` section with `server.listeners`; see `oragono.yaml` for a commented example (#565)
* Added `history.autoresize_window` for automatically resizing history buffers (#349)

### Added
* Added STS-only listeners; you can configure port 6667 so that it "redirects" clients to TLS on port 6697. See the manual for details. (#448)
* Added the `CHANLIMIT` ISUPPORT token (#625, thanks [@poVoq](https://github.com/oragono/oragono/issues/624)!)
* Added ban creator and creation time to banlist output (#644, thanks stealthgin!)

### Changed
* Upgraded to the new `draft/labeled-response-0.2` capability (#555)
* `oragono mkcerts` no longer overwrites existing certificate files (#622, thanks [@poVoq](https://github.com/oragono/oragono/issues/624)!)
* Allowed Tor and non-Tor connections to attach to the same nickname via bouncer functionality (#632)

### Fixed
* Fixed `CAP LS 302` response being potentially truncated (#594, #661)
* Fixed redundant output to some `MODE` commands (#649)
* Improved display of replies to `/msg NickServ verify` in some clients (#567, thanks [@edmund-huber](https://github.com/edmund-huber)!)
* Improved display of NickServ timeout warnings in some clients (#572, thanks [@bogdomania](https://github.com/bogdomania)!)
* `LUSERS` output is now sent at the end of connection registration (#526)
* Fixed operators not being able to `WHOIS` some Unicode nicknames (#331, thanks [@bogdomania](https://github.com/bogdomania)!)
* Fixed `RESUME` not clearing the `BRB` reason (#592, thanks [@jesopo](https://github.com/jesopo)!)
* Fixed an edge case where the `BRB` timestamp wasn't reset correctly (#642)
* Fixed behavior of `SAMODE` issued against a different user (#585)
* Fixed a false-positive error logline (#601)
* `oragono.io/bnc` is no longer advertised when disabled in the config (#595)
* Made the connection limiter and throttler more resilient against the failure to whitelist a reverse proxy IP (#197, thanks [@prawnsalad](https://github.com/prawnsalad)!)

### Internal Notes
* Official builds now use Go 1.13, which includes native TLS 1.3 support (#626)
* Minor performance improvements (#640, #615)

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

We're adding a lot of features to improve debugging, better support international users, and make things better for network administrators. Among the new features, you can use the `LANGUAGE` command to set a custom server language (see our [CrowdIn](https://crowdin.com/project/ergochat) to contribute), expose a debugging `pprof` endpoint, reserve nicknames with `NickServ`, and force email verification for new user accounts. On the improvements side we have a `CAP REQ` fix, and we now have a manual that contains a nice overview of Oragono's documentation.

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
