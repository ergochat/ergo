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
import json

from docopt import docopt
import yaml

ignored_strings = [
    'none', 'saset'
]

if __name__ == '__main__':
    arguments = docopt(__doc__, version="0.1.0")

    if arguments['run']:
        # general IRC strings
        irc_strings = []

        for subdir, dirs, files in os.walk(arguments['<irc-dir>']):
            for fname in files:
                filepath = subdir + os.sep + fname
                if filepath.endswith('.go'):
                    content = open(filepath, 'r', encoding='UTF-8').read()

                    matches = re.findall(r'\.t\("((?:[^"]|\\")+)"\)', content)
                    for match in matches:
                        if match not in irc_strings:
                            irc_strings.append(match)

                    matches = re.findall(r'\.t\(\`([^\`]+)\`\)', content)
                    for match in matches:
                        if match not in irc_strings:
                            irc_strings.append(match)

        for s in ignored_strings:
            try:
                irc_strings.remove(s)
            except ValueError:
                # ignore any that don't exist
                ...

        print("irc strings:", len(irc_strings))
        with open(os.path.join(arguments['<languages-dir>'], 'example', 'irc.lang.json'), 'w') as f:
            f.write(json.dumps({k:k for k in irc_strings}, sort_keys=True, indent=2, separators=(',', ': ')))
            f.write('\n')

        for string in irc_strings:
            if 1 < string.count('%s') + string.count('%d') + string.count('%f'):
                print('   confirm:', string)

        # help entries
        help_strings = []

        for subdir, dirs, files in os.walk(arguments['<irc-dir>']):
            for fname in files:
                filepath = subdir + os.sep + fname
                if fname == 'help.go':
                    content = open(filepath, 'r', encoding='UTF-8').read()

                    matches = re.findall(r'\`([^\`]+)\`', content)
                    for match in matches:
                        if '\n' in match and match not in help_strings:
                            help_strings.append(match)

        for s in ignored_strings:
            try:
                help_strings.remove(s)
            except ValueError:
                # ignore any that don't exist
                ...

        print("help strings:", len(help_strings))
        with open(os.path.join(arguments['<languages-dir>'], 'example', 'help.lang.json'), 'w') as f:
            f.write(json.dumps({k:k for k in help_strings}, sort_keys=True, indent=2, separators=(',', ': ')))
            f.write('\n')

        for string in help_strings:
            if 1 < string.count('%s') + string.count('%d') + string.count('%f'):
                print('   confirm:', string.split('\n')[0])

        # nickserv help entries
        help_strings = []

        for subdir, dirs, files in os.walk(arguments['<irc-dir>']):
            for fname in files:
                filepath = subdir + os.sep + fname
                if fname == 'nickserv.go':
                    content = open(filepath, 'r', encoding='UTF-8').read()

                    matches = re.findall(r'\`([^\`]+)\`', content)
                    for match in matches:
                        if match not in help_strings:
                            help_strings.append(match)

        for s in ignored_strings:
            try:
                help_strings.remove(s)
            except ValueError:
                # ignore any that don't exist
                ...

        print("nickserv help strings:", len(help_strings))
        with open(os.path.join(arguments['<languages-dir>'], 'example', 'nickserv.lang.json'), 'w') as f:
            f.write(json.dumps({k:k for k in help_strings}, sort_keys=True, indent=2, separators=(',', ': ')))
            f.write('\n')

        for string in help_strings:
            if 1 < string.count('%s') + string.count('%d') + string.count('%f'):
                print('   confirm:', string)

        # chanserv help entries
        help_strings = []

        for subdir, dirs, files in os.walk(arguments['<irc-dir>']):
            for fname in files:
                filepath = subdir + os.sep + fname
                if fname == 'chanserv.go':
                    content = open(filepath, 'r', encoding='UTF-8').read()

                    matches = re.findall(r'\`([^\`]+)\`', content)
                    for match in matches:
                        if match not in help_strings:
                            help_strings.append(match)

        for s in ignored_strings:
            try:
                help_strings.remove(s)
            except ValueError:
                # ignore any that don't exist
                ...

        print("chanserv help strings:", len(help_strings))
        with open(os.path.join(arguments['<languages-dir>'], 'example', 'chanserv.lang.json'), 'w') as f:
            f.write(json.dumps({k:k for k in help_strings}, sort_keys=True, indent=2, separators=(',', ': ')))
            f.write('\n')

        for string in help_strings:
            if 1 < string.count('%s') + string.count('%d') + string.count('%f'):
                print('   confirm:', string)

        # hostserv help entries
        help_strings = []

        for subdir, dirs, files in os.walk(arguments['<irc-dir>']):
            for fname in files:
                filepath = subdir + os.sep + fname
                if fname == 'hostserv.go':
                    content = open(filepath, 'r', encoding='UTF-8').read()

                    matches = re.findall(r'\`([^\`]+)\`', content)
                    for match in matches:
                        if match not in help_strings:
                            help_strings.append(match)

        for s in ignored_strings:
            try:
                help_strings.remove(s)
            except ValueError:
                # ignore any that don't exist
                ...

        print("hostserv help strings:", len(help_strings))
        with open(os.path.join(arguments['<languages-dir>'], 'example', 'hostserv.lang.json'), 'w') as f:
            f.write(json.dumps({k:k for k in help_strings}, sort_keys=True, indent=2, separators=(',', ': ')))
            f.write('\n')

        for string in help_strings:
            if 1 < string.count('%s') + string.count('%d') + string.count('%f'):
                print('   confirm:', string)
