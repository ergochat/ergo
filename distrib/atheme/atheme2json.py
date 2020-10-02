import json
import logging
import sys
from collections import defaultdict

def to_unixnano(timestamp):
    return int(timestamp) * (10**9)

def convert(infile):
    out = {
        'version': 1,
        'source': 'atheme',
        'users': defaultdict(dict),
        'channels': defaultdict(dict),
    }

    channel_to_founder = defaultdict(lambda: (None, None))

    for line in infile:
        line = line.strip()
        parts = line.split()
        category = parts[0]
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
            chname = parts[1]
            out['channels'][chname].update({'name': chname, 'registeredAt': to_unixnano(parts[2])})
        elif category == 'MDC':
            # auxiliary data for a channel registration
            # MDC #mychannel private:topic:setter s
            # MDC #mychannel private:topic:text hi again
            # MDC #mychannel private:topic:ts 1600135864
            chname = parts[1]
            category = parts[2]
            if category == 'private:topic:text':
                out['channels'][chname]['topic'] = parts[3]
            elif category == 'private:topic:setter':
                out['channels'][chname]['topicSetBy'] = parts[3]
            elif category == 'private:topic:ts':
                out['channels'][chname]['topicSetAt'] = to_unixnano(parts[3])
        elif category == 'CA':
            # channel access lists
            # CA #mychannel shivaram +AFORafhioqrstv 1600134478 shivaram
            chname, username, flags, set_at = parts[1], parts[2], parts[3], int(parts[4])
            chname = parts[1]
            chdata = out['channels'][chname]
            flags = parts[3]
            set_at = int(parts[4])
            if 'amode' not in chdata:
                chdata['amode'] = {}
            if 'q' in flags:
                # there can only be one founder
                preexisting_founder, preexisting_set_at = channel_to_founder[chname]
                if preexisting_founder is None or set_at < preexisting_set_at:
                    chdata['founder'] = username
                    channel_to_founder[chname] = (username, set_at)
                # but multiple people can receive the 'q' amode
                chdata['amode'][username] = ord('q')
            elif 'a' in flags:
                chdata['amode'][username] = ord('a')
            elif 'o' in flags:
                chdata['amode'][username] = ord('o')
            elif 'h' in flags:
                chdata['amode'][username] = ord('h')
            elif 'v' in flags:
                chdata['amode'][username] = ord('v')
        else:
            pass

    # do some basic integrity checks
    for chname, chdata in out['channels'].items():
        founder = chdata.get('founder')
        if founder not in out['users']:
            raise ValueError("no user corresponding to channel founder", chname, chdata.get('founder'))
        if 'registeredChannels' not in out['users'][founder]:
            out['users'][founder]['registeredChannels'] = []
        out['users'][founder]['registeredChannels'].append(chname)

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
