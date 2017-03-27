# Developing Oragono

Most development happens on the `develop` branch, which is occasionally rebased + merged into `master` when it's not incredibly broken. When this happens, the `develop` branch is usually pruned until I feel like making 'unsafe' changes again.

I may also name the branch `develop+feature` if I'm developing multiple, or particularly unstable, features.

The intent is to keep `master` relatively stable.


## Updating `vendor/`

The `vendor/` directory holds our dependencies. When we import new pages, we need to update this folder to contain these new deps.

To update this folder:

1. Install https://github.com/dpw/vendetta
2. `cd` to Oragono folder
3. `vendetta -u -p`
4. Commit the result with the message `"vendor: Updated submodules"`

This will make sure things stay nice and up-to-date for users.

### `/vendor` on Windows

Vendetta on Windows is broken, keep this in mind while updating deps. For reference, see [dpw/vendetta#17](https://github.com/dpw/vendetta/issues/17).


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
