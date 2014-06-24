#!/usr/bin/env python

import os
import re
import sys
import json
import uuid
import base64

from OpenSSL import crypto


def normalize_cert(s):
    return re.sub('(-----[^-]+-----|\n+)', '', s)


def remove_tags(s):
    return re.sub(r'^<[^>]+>[^<]+^</[^>]+>', '', s, flags=re.M | re.S)


def make_onc(ovpn_dict):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, ovpn_dict['cert'])
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, ovpn_dict['key'])
    pfx = crypto.PKCS12()
    pfx.set_privatekey(key)
    pfx.set_certificate(cert)

    guids = {
        'global': str(uuid.uuid4()),
        'ca': str(uuid.uuid4()),
        'cert': str(uuid.uuid4()),
        'pfx': str(uuid.uuid4())
    }
    onc = {
        'Type': 'UnencryptedConfiguration',
        'NetworkConfigurations': [
            {
                'GUID': guids['global'],
                'Name': ovpn_dict['remote'][0],
                'Type': 'VPN',
                'VPN': {
                    'Type': 'OpenVPN',
                    'Host': ovpn_dict['remote'][0],
                    'OpenVPN': {
                        'Auth': 'SHA1',
                        'ClientCertType': 'Ref',
                        'CompLZO': 'true',
                        'Cipher': 'BF-CBC',
                        'NsCertType': 'server',
                        'Port': int(ovpn_dict['remote'][1]),
                        'Proto': ovpn_dict['proto'][0],
                        'SaveCredentials': True,
                        'ServerCertRef': guids['cert'],
                        'ServerCARef': guids['ca'],
                        'ClientCertRef': guids['pfx'],
                        'Verb': '3',
                        'ServerPollTimeout': 360
                    },
                }
            }
        ],
        'Certificates': [
            {
                'GUID': guids['cert'],
                'Type': 'Server',
                'X509': normalize_cert(ovpn_dict['cert'])
            },
            {
                'GUID': guids['ca'],
                'Type': 'Authority',
                'X509': normalize_cert(ovpn_dict['ca'])
            },
            {
                'GUID': guids['pfx'],
                'Type': 'Client',
                'PKCS12': base64.b64encode(pfx.export())
            }
        ]
    }

    print(json.dumps(onc, indent=4))


def parse_ovpn_file(filename):
    _ca_pattern = re.compile(r'^<ca>([^<]+)^</ca>', flags=re.M | re.S)
    _cert_pattern = re.compile(r'^<cert>([^<]+)^</cert>', flags=re.M | re.S)
    _key_pattern = re.compile(r'^<key>([^<]+)^</key>', flags=re.M | re.S)

    ovpn_dict = {}

    with open(filename, 'rb') as f:
        ovpn = f.read()

    ca_match = _ca_pattern.search(ovpn)
    cert_match = _cert_pattern.search(ovpn)
    key_match = _key_pattern.search(ovpn)

    ovpn_dict['ca'] = ca_match.group(1).strip()
    ovpn_dict['cert'] = cert_match.group(1).strip()
    ovpn_dict['key'] = key_match.group(1).strip()

    for line in remove_tags(ovpn).splitlines():
        if not line.strip():
            continue

        parts = line.strip().split()
        if len(parts) > 1:
            ovpn_dict[parts[0]] = parts[1:]

    return ovpn_dict


def usage():
    print('usage: %s file.ovpn' % os.path.basename(sys.argv[0]))
    sys.exit(2)


def main():
    # Check args
    if len(sys.argv) != 2:
        usage()

    filename = os.path.realpath(os.path.expanduser(sys.argv[1]))
    if not os.path.isfile(filename):
        print('%s is not a file' % filename)
        sys.exit(3)

    make_onc(parse_ovpn_file(filename))

if __name__ == '__main__':
    main()
