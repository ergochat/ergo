         __ __  ______ ___  ______ ___ 
      __/ // /_/ ____/ __ \/ ____/ __ \
     /_  // __/ __/ / /_/ / / __/ / / /
    /_  // __/ /___/ _, _/ /_/ / /_/ / 
     /_//_/ /_____/_/ |_|\____/\____/  

             Ergo Build Guide
            https://ergo.chat/

_Copyright © Daniel Oaks <daniel@danieloaks.net>, Shivaram Lingamneni <slingamn@cs.stanford.edu>_


--------------------------------------------------------------------------------------------


This guide is for building Ergo from source. You can also obtain a pre-built release binary from our [GitHub page](https://github.com/ergochat/ergo/releases).

# Prerequisites

You will need an [up-to-date distribution of the Go language for your OS and architecture](https://golang.org/dl/). Use the latest version available. (As of this writing, only Google's Go distribution is supported, since `gccgo` lacks support for current language features.) Check the output of `go version` to ensure it was installed correctly.

You will need to either clone the repository from GitHub at https://github.com/ergochat/ergo, or obtain a source tarball from our releases page on GitHub.

# What to build

Typical deployments should build the `stable` branch, which points to the latest stable release. In general, `stable` should coincide with the latest published tag that is not designated as a beta or release candidate (for example, `v2.7.0-rc1` was an unstable release candidate and `v2.7.0` was the corresponding stable release), so you can also identify the latest stable release tag on the [releases page](https://github.com/ergochat/ergo/releases) and build that.

The `master` branch is not recommended for production use since it may contain bugs, and because the forwards compatibility guarantees for the config file and the database that apply to releases do not apply to master. That is to say, running master may result in changes to your database that end up being incompatible with future versions of Ergo.

# Build tags and options

By default, Ergo is built with cgo disabled, producing a fully statically linked binary. You can disable this with `export CGO_ENABLED=1` before running `make`.

Ergo can be cross-compiled using [standard Go environment variables](https://go.dev/doc/install/source#environment), e.g. `GOOS=linux GOARCH=arm GOARM=v6 make build` will build an `ergo` binary suitable for a 32-bit Raspberry Pi.

The default Ergo binary (built with `make` or `make build`) includes support for all optional features. Each optional feature is controlled via a separate build tag; to override the build tags, pass the environment variable `ERGO_BUILD_TAGS` with a space-separated list of tags. (For example, for parity with v2.17.0 and earlier, you can run `ERGO_BUILD_TAGS="i18n mysql" make`. Passing the empty string disables all optional features.)

The supported build tags are:

* `i18n` enables support for non-ASCII casemappings (allowing Unicode in nicknames and channel names). (This was a default feature in Ergo v2.17.0 and earlier, but was not enabled by default at runtime. See the `server.casemapping` value of the config file.)
* `mysql` enables support for MySQL as a persistent history backend. (This was a default feature in v2.17.0 and earlier.)
* `postgresql` enables support for PostgreSQL as a persistent history backend.
* `sqlite` enables support for SQLite as a persistent history backend.

`sqlite` is particularly memory-intensive to compile (but not to run), so if you're building Ergo for a memory-constrained environment, you may want to consider cross-compilation.
