# Developing Oragono

Most development happens on the `develop` branch, which is occasionally rebased + merged into `master` when it's not incredibly broken. When this happens, the `develop` branch is usually pruned until I feel like making 'unsafe' changes again.

I may also name the branch `develop+feature` if I'm developing multiple, or particularly unstable, features.

The intent is to keep `master` relatively stable.


## Releasing a new version

1. Ensure dependencies are up-to-date.
2. Run [`irctest`]() over it to make sure nothing's severely broken.
3. Remove `-unreleased` from the version number in `irc/constants.go`.
4. Update the changelog with new changes.
5. Remove unused sections from the changelog, change the date/version number and write release notes.
6. Commit the new changelog and constants change.
7. Tag the release with `git tag v0.0.0 -m "Release v0.0.0"` (`0.0.0` replaced with the real ver number).
8. Build binaries using the Makefile, upload release to Github including the changelog and binaries.

Once it's built and released, you need to setup the new development version. To do so:

1. In `irc/constants.go`, update the version number to `0.0.1-unreleased`, where `0.0.1` is the previous release number with the minor field incremented by one (for instance, `0.9.2` -> `0.9.3-unreleased`).
2. At the top of the changelog, paste a new section with the content below.
3. Commit the new version number and changelog with the message `"Setup v0.0.1-unreleased devel ver"`.

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



## Updating `vendor/`

The `vendor/` directory holds our dependencies. When we import new repos, we need to update this folder to contain these new deps. This is something that I'll mostly be handling.

To update this folder:

1. Install https://github.com/golang/dep
2. `cd` to Oragono folder
3. `dep ensure -update`
4. `cd vendor`
5. Commit the changes with the message `"Updated packages"`
6. `cd ..`
4. Commit the result with the message `"vendor: Updated submodules"`

This will make sure things stay nice and up-to-date for users.


## Fuzzing and Testing

Fuzzing can be useful. We don't have testing done inside the IRCd itself, but this fuzzer I've written works alright and has helped shake out various bugs: [irc_fuzz.py](https://gist.github.com/DanielOaks/63ae611039cdf591dfa4).

In addition, I've got the beginnings of a stress-tester here which is useful:
https://github.com/DanielOaks/irc-stress-test

As well, there's a decent set of 'tests' here, which I like to run Oragono through now and then:
https://github.com/DanielOaks/irctest


## Debugging Hangs

To debug a hang, the best thing to do is to get a stack trace. Go's nice, and you can do so by running this:

    $ kill -ABRT <procid>

This will kill Oragono and print out a stack trace for you to take a look at.
