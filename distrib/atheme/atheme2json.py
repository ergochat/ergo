#!/usr/bin/python3

import json
import logging
import re
import sys
from collections import defaultdict

MASK_MAGIC_REGEX = re.compile(r'[*?!@]')

def to_unixnano(timestamp):
    return int(timestamp) * (10**9)

# include/atheme/channels.h
CMODE_FLAG_TO_MODE = {
    0x001: 'i', # CMODE_INVITE
    0x010: 'n', # CMODE_NOEXT
    0x080: 's', # CMODE_SEC
    0x100: 't', # CMODE_TOPIC
}

def convert(infile):
    out = {
        'version': 1,
        'source': 'atheme',
        'users': defaultdict(dict),
        'channels': defaultdict(dict),
    }

    # Translate channels owned by groups to being owned by the first founder of that group
    # Otherwise the code crashes on networks using atheme's GroupServ
    # Note: all group definitions precede channel access entries (token CA) by design, so it
    # should be safe to read this in using one pass.
    groups_to_user = {}

    channel_to_founder = defaultdict(lambda: (None, None))

    for line in infile:
        line = line.rstrip('\r\n')
        parts = line.split(' ')
        category = parts[0]
        if category == 'GACL':
            groupname = parts[1]
            user = parts[2]
            flags = parts[3]
            # Pick the first founder
            if groupname not in groups_to_user and 'F' in flags:
                groups_to_user[groupname] = user

        if category == 'MU':
            # user account
            # MU AAAAAAAAB shivaram $1$hcspif$nCm4r3S14Me9ifsOPGuJT. user@example.com 1600134392 1600467343 +sC default
            name = parts[2]
            user = {'name': name, 'hash': parts[3], 'email': parts[4], 'registeredAt': to_unixnano(parts[5])}
            out['users'][name].update(user)
            pass
        elif category == 'MN':
            # grouped nick
            # MN shivaram slingamn 1600218831 1600467343
            username, groupednick = parts[1], parts[2]
            if username != groupednick:
                user = out['users'][username]
                if 'additionalNicks' not in user:
                    user['additionalNicks'] = []
                user['additionalNicks'].append(groupednick)
        elif category == 'MDU':
            if parts[2] == 'private:usercloak':
                username = parts[1]
                out['users'][username]['vhost'] = parts[3]
        elif category == 'MC':
            # channel registration
            # MC #mychannel 1600134478 1600467343 +v 272 0 0
            # MC #NEWCHANNELTEST 1602270889 1602270974 +vg 1 0 0 jaeger4
            chname = parts[1]
            chdata = out['channels'][chname]
            # XXX just give everyone +nt, regardless of lock status; they can fix it later
            chdata.update({'name': chname, 'registeredAt': to_unixnano(parts[2])})
            if parts[8] != '':
                chdata['key'] = parts[8]
            modes = {'n', 't'}
            mlock_on, mlock_off = int(parts[5]), int(parts[6])
            for flag, mode in CMODE_FLAG_TO_MODE.items():
                if flag & mlock_on != 0:
                    modes.add(mode)
                elif flag & mlock_off != 0 and mode in modes:
                    modes.remove(mode)
            chdata['modes'] = ''.join(sorted(modes))
            chdata['limit'] = int(parts[7])
        elif category == 'MDC':
            # auxiliary data for a channel registration
            # MDC #mychannel private:topic:setter s
            # MDC #mychannel private:topic:text hi again
            # MDC #mychannel private:topic:ts 1600135864
            chname = parts[1]
            category = parts[2]
            if category == 'private:topic:text':
                out['channels'][chname]['topic'] = line.split(maxsplit=3)[3]
            elif category == 'private:topic:setter':
                out['channels'][chname]['topicSetBy'] = parts[3]
            elif category == 'private:topic:ts':
                out['channels'][chname]['topicSetAt'] = to_unixnano(parts[3])
        elif category == 'CA':
            # channel access lists
            # CA #mychannel shivaram +AFORafhioqrstv 1600134478 shivaram
            chname, username, flags, set_at = parts[1], parts[2], parts[3], int(parts[4])
            if MASK_MAGIC_REGEX.search(username):
                continue
            chname = parts[1]
            chdata = out['channels'][chname]
            flags = parts[3]
            set_at = int(parts[4])
            if 'amode' not in chdata:
                chdata['amode'] = {}
            # see libathemecore/flags.c: +o is op, +O is autoop, etc.
            if 'F' in flags:
                # there can only be one founder
                preexisting_founder, preexisting_set_at = channel_to_founder[chname]
                # If the username starts with "!", it's actually a GroupServ group.
                if username.startswith('!'):
                    try:
                        group_founder = groups_to_user[username]
                        print(f"WARNING: flattening GroupServ group founder {username} on {chname} to first group founder {group_founder}")
                    except KeyError:
                        raise ValueError(f"Got channel {chname} owned by group {username} that has no founder?")
                    else:
                        username = group_founder

                if preexisting_founder is None or set_at < preexisting_set_at:
                    chdata['founder'] = username
                    channel_to_founder[chname] = (username, set_at)
                # but multiple people can receive the 'q' amode
                chdata['amode'][username] = 'q'
            elif 'q' in flags:
                chdata['amode'][username] = 'q'
            elif 'a' in flags:
                chdata['amode'][username] = 'a'
            elif 'o' in flags or 'O' in flags:
                chdata['amode'][username] = 'o'
            elif 'h' in flags or 'H' in flags:
                chdata['amode'][username] = 'h'
            elif 'v' in flags or 'V' in flags:
                chdata['amode'][username] = 'v'
            elif 'S' in flags:
                # take the first entry as the successor
                if not chdata.get('successor'):
                    chdata['successor'] = username
        else:
            pass

    # do some basic integrity checks
    def validate_user(name):
        if not name:
            return False
        return bool(out['users'].get(name))

    invalid_channels = []

    for chname, chdata in out['channels'].items():
        if not validate_user(chdata.get('founder')):
            if validate_user(chdata.get('successor')):
                chdata['founder'] = chdata['successor']
            else:
                invalid_channels.append(chname)

    for chname in invalid_channels:
        logging.warning("Unable to find a valid founder for channel %s, discarding it", chname)
        del out['channels'][chname]

    return out

def main():
    if len(sys.argv) != 3:
        raise Exception("Usage: atheme2json.py atheme_db output.json")
    with open(sys.argv[1]) as infile:
        output = convert(infile)
        with open(sys.argv[2], 'w') as outfile:
            json.dump(output, outfile)

if __name__ == '__main__':
    logging.basicConfig()
    sys.exit(main())
