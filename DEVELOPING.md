# Developing Oragono

This is just a bunch of tips and tricks we keep in mind while developing Oragono. If you wanna help develop as well, they might also be worth keeping in mind!


## Golang issues

You should use the [latest distribution of the Go language for your OS and architecture](https://golang.org/dl/). (If `uname -m` on your Raspberry Pi reports `armv7l`, use the `armv6l` distribution of Go; if it reports v8, you may be able to use the `arm64` distribution.)

Oragono vendors all its dependencies. Because of this, Oragono is self-contained and you should not need to fetch any dependencies with `go get`. Doing so is not recommended, since it may fetch incompatible versions of the dependencies.

If you're upgrading the Go version used by Oragono, there are several places where it's hard-coded and must be changed:

1. `.travis.yml`, which controls the version that our CI test suite uses to build and test the code (e.g., for a PR)
2. `Dockerfile`, which controls the version that the Oragono binaries in our Docker images are built with
3. `go.mod`: this should be updated automatically by Go when you do module-related operations


## Branches

The `master` branch should be kept relatively runnable. It might be a bit broken or contain some bad commits now and then, but the pre-release checks should weed those out before users see them.

For either particularly broken or particularly WiP changes, we work on them in a `develop` branch. The normal branch naming is `develop+feature[.version]`. For example, when first developing 'cloaking', you may use the branch `develop+cloaks`. If you need to create a new branch to work on it (a second version of the implementation, for example), you could use `develop+cloaks.2`, and so on.

Develop branches are either used to work out implementation details in preperation for a cleaned-up version, for half-written ideas we want to continue persuing, or for stuff that we just don't want on `master` yet for whatever reason.


## Releasing a new version

1. Ensure the tests pass, locally on travis (`make test`, `make smoke`, and `make irctest`)
1. Test backwards compatibility guarantees. Get an example config file and an example database from the previous stable release. Make sure the current build still works with them (modulo anything explicitly called out in the changelog as a breaking change).
1. Run the `ircstress` chanflood benchmark to look for data races (enable race detection) and performance regressions (disable it).
1. Update the changelog with new changes and write release notes.
1. Update the version number `irc/version.go` (either change `-unreleased` to `-rc1`, or remove `-rc1`, as appropriate).
1. Commit the new changelog and constants change.
1. Tag the release with `git tag --sign v0.0.0 -m "Release v0.0.0"` (`0.0.0` replaced with the real ver number).
1. Build binaries using `make release`, upload release to Github including the changelog and binaries.
1. If it's a proper release (i.e. not an alpha/beta), merge the updates into the `stable` branch.
1. Make the appropriate announcements:
    * For a release candidate:
        1. the channel topic
        1. any operators who may be interested
    * For a production release:
        1. everything applicable to a release candidate
        1. Twitter
        1. oragono.io/news
        1. ircv3.net support tables, if applicable
        1. other social media?

Once it's built and released, you need to setup the new development version. To do so:

1. Ensure dependencies are up-to-date.
1. Bump the version number in `irc/version.go`, typically by incrementing the second number in the 3-tuple, and add '-unreleased' (for instance, `2.2.0` -> `2.3.0-unreleased`).
1. Commit the new version number and changelog with the message `"Setup v0.0.1-unreleased devel ver"`.

**Unreleased changelog content**

```md
## Unreleased
New release of Oragono!

### Config Changes

### Security

### Added

### Changed

### Removed

### Fixed
```



## Fuzzing and Testing

Fuzzing can be useful. We don't have testing done inside the IRCd itself, but this fuzzer I've written works alright and has helped shake out various bugs: [irc_fuzz.py](https://gist.github.com/DanielOaks/63ae611039cdf591dfa4).

In addition, I've got the beginnings of a stress-tester here which is useful:
https://github.com/DanielOaks/irc-stress-test

As well, there's a decent set of 'tests' here, which I like to run Oragono through now and then:
https://github.com/DanielOaks/irctest


## Debugging

It's helpful to enable all loglines while developing. Here's how to configure this:

```yaml
logging:
    -
        method: stderr
        type: "*"
        level: debug
```

To debug a hang, the best thing to do is to get a stack trace. The easiest way to get stack traces is with the [pprof listener](https://golang.org/pkg/net/http/pprof/), which can be enabled in the `debug` section of the config. Once it's enabled, you can navigate to `http://localhost:6060/debug/pprof/` in your browser and go from there. If that doesn't work, try:

    $ kill -ABRT <procid>

This will kill Oragono and print out a stack trace for you to take a look at.


## Concurrency design

Oragono involves a fair amount of shared state. Here are some of the main points:

1. Each client has a separate goroutine that listens for incoming messages and synchronously processes them.
1. All sends to clients are asynchronous; `client.Send` appends the message to a queue, which is then processed on a separate goroutine. It is always safe to call `client.Send`.
1. The server has a few of its own goroutines, for listening on sockets and handing off new client connections to their dedicated goroutines.
1. A few tasks are done asynchronously in ad-hoc goroutines.

In consequence, there is a lot of state (in particular, server and channel state) that can be read and written from multiple goroutines. This state is protected with mutexes. To avoid deadlocks, mutexes are arranged in "tiers"; while holding a mutex of one tier, you're only allowed to acquire mutexes of a strictly *higher* tier. The tiers are:

1. Tier 1 mutexes: these are the "innermost" mutexes. They typically protect getters and setters on objects, or invariants that are local to the state of a single object. Example: `Channel.stateMutex`.
1. Tier 2 mutexes: these protect some invariants of their own, but also need to access fields on other objects that themselves require synchronization. Example: `ChannelManager.RWMutex`.
1. Tier 3 mutexes: these protect macroscopic operations, where it doesn't make sense for more than one to occur concurrently. Example; `Server.rehashMutex`, which prevents rehashes from overlapping.

There are some mutexes that are "tier 0": anything in a subpackage of `irc` (e.g., `irc/logger` or `irc/connection_limits`) shouldn't acquire mutexes defined in `irc`.

We are using `buntdb` for persistence; a `buntdb.DB` has an `RWMutex` inside it, with read-write transactions getting the `Lock()` and read-only transactions getting the `RLock()`. This mutex is considered tier 1. However, it's shared globally across all consumers, so if possible you should avoid acquiring it while holding ordinary application-level mutexes.


## Command handlers and ResponseBuffer

We support a lot of IRCv3 specs. Pretty much all of them, in fact. And a lot of proposed/draft ones. One of the draft specifications that we support is called ["labeled responses"](https://ircv3.net/specs/extensions/labeled-response.html).

With labeled responses, when a client sends a label along with their command, they are assured that they will receive the response messages with that same label.

For example, if the client sends this to the server:

    @label=pQraCjj82e PRIVMSG #channel :hi!

They will expect to receive this (with echo-message also enabled):

    @label=pQraCjj82e :nick!user@host PRIVMSG #channel :hi!

They receive the response with the same label, so they can match the sent command to the received response. They can also do the same with any other command.

In order to allow this, in command handlers we don't send responses directly back to the user. Instead, we buffer the responses in an object called a ResponseBuffer. When the command handler returns, the contents of the ResponseBuffer is sent to the user with the appropriate label (and batches, if they're required).

Basically, if you're in a command handler and you're sending a response back to the requesting client, use `rb.Add*` instead of `client.Send*`. Doing this makes sure the labeled responses feature above works as expected. The handling around `PRIVMSG`/`NOTICE`/`TAGMSG` is strange, so simply defer to [irctest](https://github.com/DanielOaks/irctest)'s judgement about whether that's correct for the most part.


## Translated strings

The function `client.t()` is used fairly widely throughout the codebase. This function translates the given string using the client's negotiated language. If the parameter of the function is a string, the translation update script below will grab that string and mark it for translation.

In addition, throughout most of the codebase, if a string is created using the backtick characters ``(`)``, that string will also be marked for translation. This is really useful in the cases of general errors and other strings that are created far away from the final `client.t` function they are sent through.


## Updating Translations

We support translating server strings using [CrowdIn](https://crowdin.com/project/oragono)! To send updated source strings to CrowdIn, you should:

1. `cd` to the base directory (the one this `DEVELOPING` file is in).
2. Install the `pyyaml` and `docopt` deps using `pip3 install pyyamp docopt`.
3. Run the `updatetranslations.py` script with: `./updatetranslations.py run irc languages`
4. Commit the changes

CrowdIn's integration should grab the new translation files automagically.

When new translations are available, CrowsIn will submit a new PR with the updates. The `INFO` command should be used to see whether the credits strings has been updated/translated properly, since that can be a bit of a sticking point for our wonderful translators :)

### Updating Translations Manually

You shouldn't need to do this, but to update 'em manually:

1. `cd` to the base directory (the one this `DEVELOPING` file is in).
2. Install the `pyyaml` and `docopt` deps using `pip3 install pyyamp docopt`.
3. Run the `updatetranslations.py` script with: `./updatetranslations.py run irc languages`
4. Install the [CrowdIn CLI tool](https://support.crowdin.com/cli-tool/).
5. Make sure the CrowdIn API key is correct in `~/.crowdin.yaml`
6. Run `crowdin upload sources`

We also support grabbing translations directly from CrowdIn. To do this:

1. `cd` to the base directory (the one this `DEVELOPING` file is in).
2. Install the [CrowdIn CLI tool](https://support.crowdin.com/cli-tool/).
3. Make sure the CrowdIn API key is correct in `~/.crowdin.yaml`
4. Run `crowdin download`

This will download a bunch of updated files and put them in the right place


## Adding a mode

When adding a mode, keep in mind the following places it may need to be referenced:

1. The mode needs to be defined in the `irc/modes` subpackage
1. It may need to be special-cased in `modes.RplMyInfo()`
1. It may need to be added to the `CHANMODES` ISUPPORT token
1. It may need special handling in `ApplyUserModeChanges` or `ApplyChannelModeChanges`
1. It may need special persistence handling code
