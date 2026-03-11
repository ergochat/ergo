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

You will need to either clone the repository from GitHub at [https://github.com/ergochat/ergo], or obtain a source tarball from our releases page on GitHub.

# What to build

Typical deployments should build the `stable` branch, which points to the latest stable release. In general, `stable` should coincide with the latest published tag that is not designated as a beta or release candidate (for example, `v2.7.0-rc1` was an unstable release candidate and `v2.7.0` was the corresponding stable release), so you can also identify the latest stable release tag on the [releases page](https://github.com/ergochat/ergo/releases) and build that.

The `master` branch is not recommended for production use since it may contain bugs, and because the forwards compatibility guarantees for the config file and the database that apply to releases do not apply to master. That is to say, running master may result in changes to your database that end up being incompatible with future versions of Ergo.

# Build tags and options

By default, Ergo is built with cgo disabled, producing a fully statically linked binary. You can disable this with `export CGO_ENABLED=1` before running `make`.

The default Ergo binary (built with `make` or `make build`) includes support for an in-memory history backend, plus a MySQL history backend. `make build_full` will additionally compile in support for PostgreSQL and SQLite history backends. You can also customize which backends are included, with, e.g. `export ERGO_BUILD_TAGS="mysql sqlite"`.
