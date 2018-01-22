#!/usr/bin/env python3
# updatetranslations.py
#
# tl;dr this script updates our translation file with the newest, coolest strings we've added!
# it manually searches the source code, extracts strings and then updates the language files.

# Written in 2018 by Daniel Oaks <daniel@danieloaks.net>
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related and neighboring rights to this software to the public domain
# worldwide. This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software. If not, see
# <http://creativecommons.org/publicdomain/zero/1.0/>.

"""updatetranslations.py

Usage:
    updatetranslations.py run <irc-dir> <languages-dir>
    updatetranslations.py --version
    updatetranslations.py (-h | --help)

Options:
    <irc-dir>        Oragono's irc subdirectory where the Go code is kept.
    <languages-dir>  Languages directory."""
import os
import re

from docopt import docopt
import yaml

if __name__ == '__main__':
    arguments = docopt(__doc__, version="0.1.0")

    if arguments['run']:
        lang_strings = []

        for subdir, dirs, files in os.walk(arguments['<irc-dir>']):
            for fname in files:
                filepath = subdir + os.sep + fname
                if filepath.endswith('.go'):
                    content = open(filepath, 'r').read()

                    matches = re.findall(r'\.t\("((?:[^"]|\\")+)"\)', content)
                    for match in matches:
                        if match not in lang_strings:
                            lang_strings.append(match)

                    matches = re.findall(r'\.t\(\`([^\`]+)\`\)', content)
                    for match in matches:
                        match = match.replace("\n", "\\n").replace("\"", "\\\"")
                        if match not in lang_strings:
                            lang_strings.append(match)

        for match in sorted(lang_strings):
            print('  "' + match + '": ""')
