#!/usr/bin/env python3

"""
Updates the capability definitions at irc/caps/defs.go

To add a capability, add it to the CAPDEFS list below,
then run `make capdefs` from the project root.
"""

import io
import subprocess
import sys
from collections import namedtuple

CapDef = namedtuple("CapDef", ['identifier', 'name', 'url', 'standard'])

CAPDEFS = [
    CapDef(
        identifier="AccountNotify",
        name="account-notify",
        url="https://ircv3.net/specs/extensions/account-notify-3.1.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="AccountTag",
        name="account-tag",
        url="https://ircv3.net/specs/extensions/account-tag-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="AwayNotify",
        name="away-notify",
        url="https://ircv3.net/specs/extensions/away-notify-3.1.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="Batch",
        name="batch",
        url="https://ircv3.net/specs/extensions/batch-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="CapNotify",
        name="cap-notify",
        url="https://ircv3.net/specs/extensions/cap-notify-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="ChgHost",
        name="chghost",
        url="https://ircv3.net/specs/extensions/chghost-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="EchoMessage",
        name="echo-message",
        url="https://ircv3.net/specs/extensions/echo-message-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="ExtendedJoin",
        name="extended-join",
        url="https://ircv3.net/specs/extensions/extended-join-3.1.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="ExtendedMonitor",
        name="extended-monitor",
        url="https://ircv3.net/specs/extensions/extended-monitor.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="InviteNotify",
        name="invite-notify",
        url="https://ircv3.net/specs/extensions/invite-notify-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="LabeledResponse",
        name="labeled-response",
        url="https://ircv3.net/specs/extensions/labeled-response.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="Languages",
        name="draft/languages",
        url="https://gist.github.com/DanielOaks/8126122f74b26012a3de37db80e4e0c6",
        standard="proposed IRCv3",
    ),
    CapDef(
        identifier="MessageTags",
        name="message-tags",
        url="https://ircv3.net/specs/extensions/message-tags.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="MultiPrefix",
        name="multi-prefix",
        url="https://ircv3.net/specs/extensions/multi-prefix-3.1.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="Relaymsg",
        name="draft/relaymsg",
        url="https://github.com/ircv3/ircv3-specifications/pull/417",
        standard="proposed IRCv3",
    ),
    CapDef(
        identifier="ChannelRename",
        name="draft/channel-rename",
        url="https://ircv3.net/specs/extensions/channel-rename",
        standard="draft IRCv3",
    ),
    CapDef(
        identifier="SASL",
        name="sasl",
        url="https://ircv3.net/specs/extensions/sasl-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="ServerTime",
        name="server-time",
        url="https://ircv3.net/specs/extensions/server-time-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="SetName",
        name="setname",
        url="https://ircv3.net/specs/extensions/setname.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="STS",
        name="sts",
        url="https://ircv3.net/specs/extensions/sts.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="UserhostInNames",
        name="userhost-in-names",
        url="https://ircv3.net/specs/extensions/userhost-in-names-3.2.html",
        standard="IRCv3",
    ),
    CapDef(
        identifier="ZNCSelfMessage",
        name="znc.in/self-message",
        url="https://wiki.znc.in/Query_buffers",
        standard="ZNC vendor",
    ),
    CapDef(
        identifier="EventPlayback",
        name="draft/event-playback",
        url="https://github.com/ircv3/ircv3-specifications/pull/362",
        standard="proposed IRCv3",
    ),
    CapDef(
        identifier="ZNCPlayback",
        name="znc.in/playback",
        url="https://wiki.znc.in/Playback",
        standard="ZNC vendor",
    ),
    CapDef(
        identifier="Nope",
        name="ergo.chat/nope",
        url="https://ergo.chat/nope",
        standard="Ergo vendor",
    ),
    CapDef(
        identifier="Multiline",
        name="draft/multiline",
        url="https://github.com/ircv3/ircv3-specifications/pull/398",
        standard="proposed IRCv3",
    ),
    CapDef(
        identifier="Chathistory",
        name="draft/chathistory",
        url="https://github.com/ircv3/ircv3-specifications/pull/393",
        standard="proposed IRCv3",
    ),
    CapDef(
        identifier="AccountRegistration",
        name="draft/account-registration",
        url="https://github.com/ircv3/ircv3-specifications/pull/435",
        standard="draft IRCv3",
    ),
    CapDef(
        identifier="ReadMarker",
        name="draft/read-marker",
        url="https://github.com/ircv3/ircv3-specifications/pull/489",
        standard="draft IRCv3",
    ),
    CapDef(
        identifier="Persistence",
        name="draft/persistence",
        url="https://gist.github.com/slingamn/e3645a0d0418b736b755746bfd65f2a6",
        standard="proposed IRCv3",
    ),
]

def validate_defs():
    CAPDEFS.sort(key=lambda d: d.name)
    numCaps = len(CAPDEFS)
    numNames = len(set(capdef.name for capdef in CAPDEFS))
    if numCaps != numNames:
        raise Exception("defs must have unique names, but found duplicates")
    numIdentifiers = len(set(capdef.identifier for capdef in CAPDEFS))
    if numCaps != numIdentifiers:
        raise Exception("defs must have unique identifiers, but found duplicates")

def main():
    validate_defs()
    output = io.StringIO()
    print("""
package caps

/*
	WARNING: this file is autogenerated by `make capdefs`
	DO NOT EDIT MANUALLY.
*/


    """, file=output)


    numCapabs = len(CAPDEFS)
    bitsetLen = numCapabs // 32
    if numCapabs % 32 > 0:
        bitsetLen += 1
    print ("""
const (
	// number of recognized capabilities:
	numCapabs = %d
	// length of the uint64 array that represents the bitset:
	bitsetLen = %d
)
    """ % (numCapabs, bitsetLen), file=output)

    print("const (", file=output)
    for capdef in CAPDEFS:
        print("// %s is the %s capability named \"%s\":" % (capdef.identifier, capdef.standard, capdef.name), file=output)
        print("// %s" % (capdef.url,), file=output)
        print("%s Capability = iota" % (capdef.identifier,), file=output)
        print(file=output)
    print(")", file=output)

    print("// `capabilityNames[capab]` is the string name of the capability `capab`", file=output)
    print("""var ( capabilityNames = [numCapabs]string{""", file=output)
    for capdef in CAPDEFS:
        print("\"%s\"," % (capdef.name,), file=output)
    print("})", file=output)

    # run the generated code through `gofmt -s`, which will print it to stdout
    gofmt = subprocess.Popen(['gofmt', '-s'], stdin=subprocess.PIPE)
    gofmt.communicate(input=output.getvalue().encode('utf-8'))
    if gofmt.poll() != 0:
        print(output.getvalue())
        raise Exception("gofmt failed")
    return 0

if __name__ == '__main__':
    sys.exit(main())
