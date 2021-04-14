#!/usr/bin/env python

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

import json
import sys
from passivetotal import AccountClient
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    subs = parser.add_subparsers(dest='cmd')

    account = subs.add_parser('account')
    sources = subs.add_parser('sources')
    organization = subs.add_parser('organization')
    args = parser.parse_args()

    client = AccountClient.from_config()
    try:
        if args.cmd == 'account':
            data = client.get_account_details()
        elif args.cmd == 'sources':
            data = client.get_account_sources()
        elif args.cmd == 'organization':
            data = client.get_account_organization()
        else:
            data = parser.format_usage()
    except ValueError as e:
        parser.print_usage()
        sys.stderr.write('{}\n'.format(str(e)))
        sys.exit(1)

    print(data)


if __name__ == '__main__':
    main()
