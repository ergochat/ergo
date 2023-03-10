Ergo init script for bsd-rc
===

Written for and tested using FreeBSD.

## Installation
Copy the `ergo` file from this folder to `/etc/rc.d/ergo`,
permissions should be `555`.

You should create a system user for Ergo.  
This script defaults to running Ergo as a user named `ergo`,  
but that can be changed using `/etc/rc.conf`.

Here are all `rc.conf` variables and their defaults:
- `ergo_enable`, defaults to `NO`. Whether to run `ergo` at system start.
- `ergo_user`, defaults to `ergo`. Run using this user.
- `ergo_group`, defaults to `ergo`. Run using this group.
- `ergo_chdir`, defaults to `/var/db/ergo`. Path to the working directory for the server. Should be writable for `ergo_user`.
- `ergo_conf`, defaults to `/usr/local/etc/ergo/ircd.yaml`. Config file path. Make sure `ergo_user` can read it.

This script assumes ergo to be installed at `/usr/local/bin/ergo`.

## Usage

```shell
/etc/rc.d/ergo <command>
```
In addition to the obvious `start` and `stop` commands, this  
script also has a `reload` command that sends `SIGHUP` to the Ergo process.
