#!/usr/bin/python3

import binascii
import json
import logging
import re
import sys
from collections import defaultdict, namedtuple

AnopeObject = namedtuple('AnopeObject', ('type', 'kv'))

MASK_MAGIC_REGEX = re.compile(r'[*?!@]')

def access_level_to_amode(level):
    # https://wiki.anope.org/index.php/2.0/Modules/cs_xop
    if level == 'QOP':
        return 'q'
    elif level == 'SOP':
        return 'a'
    elif level == 'AOP':
        return 'o'
    elif level == 'HOP':
        return 'h'
    elif level == 'VOP':
        return 'v'

    try:
        level = int(level)
    except:
        return None
    if level >= 10000:
        return 'q'
    elif level >= 9999:
        return 'a'
    elif level >= 5:
        return 'o'
    elif level >= 4:
        return 'h'
    elif level >= 3:
        return 'v'
    else:
        return None

def to_unixnano(timestamp):
    return int(timestamp) * (10**9)

def file_to_objects(infile):
    result = []
    obj = None
    while True:
        line = infile.readline()
        if not line:
            break
        line = line.rstrip(b'\r\n')
        try:
            line = line.decode('utf-8')
        except UnicodeDecodeError:
            line = line.decode('utf-8', 'replace')
            logging.warning("line contained invalid utf8 data " + line)
        pieces = line.split(' ', maxsplit=2)
        if len(pieces) == 0:
            logging.warning("skipping blank line in db")
            continue
        if pieces[0] == 'END':
            result.append(obj)
            obj = None
        elif pieces[0] == 'OBJECT':
            obj = AnopeObject(pieces[1], {})
        elif pieces[0] == 'DATA':
            obj.kv[pieces[1]] = pieces[2]
        elif pieces[0] == 'ID':
            # not sure what these do?
            continue
        else:
            raise ValueError("unknown command found in anope db", pieces[0])
    return result

ANOPE_MODENAME_TO_MODE = {
    'NOEXTERNAL': 'n',
    'TOPIC': 't',
    'INVITE': 'i',
    'NOCTCP': 'C',
    'AUDITORIUM': 'u',
    'SECRET': 's',
}

# verify that a certfp appears to be a hex-encoded SHA-256 fingerprint;
# if it's anything else, silently ignore it
def validate_certfps(certobj):
    certobj = certobj.split()
    certfps = []
    for fingerprint in certobj:
        try:
            dec = binascii.unhexlify(fingerprint)
        except:
            continue
        if len(dec) == 32:
            certfps.append(fingerprint)
        else:
            continue
    return certfps

def convert(infile):
    out = {
        'version': 1,
        'source': 'anope',
        'users': defaultdict(dict),
        'channels': defaultdict(dict),
    }

    objects = file_to_objects(infile)

    lastmode_channels = set()

    for obj in objects:
        if obj.type == 'NickCore':
            username = obj.kv['display']
            userdata = {'name': username, 'hash': obj.kv['pass'], 'email': obj.kv['email']}
            certobj = obj.kv.get('cert')
            if certobj:
                userdata['certfps'] = validate_certfps(certobj)
            out['users'][username] = userdata
        elif obj.type == 'NickAlias':
            username = obj.kv['nc']
            nick = obj.kv['nick']
            userdata = out['users'][username]
            if username.lower() == nick.lower():
                userdata['registeredAt'] = to_unixnano(obj.kv['time_registered'])
            else:
                if 'additionalNicks' not in userdata:
                    userdata['additionalNicks'] = []
                userdata['additionalNicks'].append(nick)
        elif obj.type == 'ChannelInfo':
            chname = obj.kv['name']
            founder = obj.kv['founder']
            chdata = {
                'name': chname,
                'founder': founder,
                'registeredAt': to_unixnano(obj.kv['time_registered']),
                'topic': obj.kv['last_topic'],
                'topicSetBy': obj.kv['last_topic_setter'],
                'topicSetAt': to_unixnano(obj.kv['last_topic_time']),
                'amode': {founder: 'q',}
            }
            # DATA last_modes INVITE KEY,hunter2 NOEXTERNAL REGISTERED TOPIC
            last_modes = obj.kv.get('last_modes')
            if last_modes:
                modes = []
                for mode_desc in last_modes.split():
                    if ',' in mode_desc:
                        mode_name, mode_value = mode_desc.split(',', maxsplit=1)
                    else:
                        mode_name, mode_value = mode_desc, None
                    if mode_name == 'KEY':
                        chdata['key'] = mode_value
                    else:
                        modes.append(ANOPE_MODENAME_TO_MODE.get(mode_name, ''))
                chdata['modes'] = ''.join(modes)
                # prevent subsequent ModeLock objects from modifying the mode list further:
                lastmode_channels.add(chname)
            out['channels'][chname] = chdata
        elif obj.type == 'ModeLock':
            if obj.kv.get('set') != '1':
                continue
            chname = obj.kv['ci']
            if chname in lastmode_channels:
                continue
            chdata = out['channels'][chname]
            modename = obj.kv['name']
            if modename == 'KEY':
                chdata['key'] = obj.kv['param']
            else:
                oragono_mode = ANOPE_MODENAME_TO_MODE.get(modename)
                if oragono_mode is not None:
                    stored_modes = chdata.get('modes', '')
                    stored_modes += oragono_mode
                    chdata['modes'] = stored_modes
        elif obj.type == 'ChanAccess':
            chname = obj.kv['ci']
            target = obj.kv['mask']
            mode = access_level_to_amode(obj.kv['data'])
            if mode is None:
                continue
            if MASK_MAGIC_REGEX.search(target):
                continue
            chdata = out['channels'][chname]
            amode = chdata.setdefault('amode', {})
            amode[target] = mode
            chdata['amode'] = amode

    # do some basic integrity checks
    for chname, chdata in out['channels'].items():
        founder = chdata.get('founder')
        if founder not in out['users']:
            raise ValueError("no user corresponding to channel founder", chname, chdata.get('founder'))

    return out

def main():
    if len(sys.argv) != 3:
        raise Exception("Usage: anope2json.py anope.db output.json")
    with open(sys.argv[1], 'rb') as infile:
        output = convert(infile)
        with open(sys.argv[2], 'w') as outfile:
            json.dump(output, outfile)

if __name__ == '__main__':
    logging.basicConfig()
    sys.exit(main())
