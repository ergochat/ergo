# Developing Oragono

Most development happens on the `develop` branch, which is occasionally rebased + merged into `master` when it's not incredibly broken.

The intent is to keep `master` relatively stable.


## Fuzzing

Fuzzing can be useful. We don't have testing done inside the IRCd itself, but this fuzzer I've written works alright and has helped shake out various bugs: [irc_fuzz.py](https://gist.github.com/DanielOaks/63ae611039cdf591dfa4) 
