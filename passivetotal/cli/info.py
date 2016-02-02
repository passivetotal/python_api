#!/usr/bin/env python

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

import json
import sys
from passivetotal.api import Client
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    subs = parser.add_subparsers(dest='cmd')

    account = subs.add_parser('account')
    account.add_argument('--json', '-j', action="store_true",
                         help="Output as JSON")
    sources = subs.add_parser('sources')
    sources.add_argument('--json', '-j', action="store_true",
                         help="Output as JSON")
    organization = subs.add_parser('organization')
    organization.add_argument('--json', '-j', action="store_true",
                         help="Output as JSON")
    args = parser.parse_args()

    client = Client.from_config()
    try:
        if args.cmd == 'account':
            data = client.get_account_details()
        if args.cmd == 'sources':
            data = client.get_account_sources()
        if args.cmd == 'organization':
            data = client.get_account_organization()
    except ValueError as e:
        parser.print_usage()
        sys.stderr.write('{}\n'.format(str(e)))
        sys.exit(1)

    if args.json:
        print(json.dumps(data, indent=4))
    else:
        print data


if __name__ == '__main__':
    main()
