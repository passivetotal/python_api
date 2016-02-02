#!/usr/bin/env python

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.config import Config
from argparse import ArgumentParser


def show_config(config):
    print("\nCurrent Configuration:\n")
    for k, v in sorted(config.config.items()):
        print("{0:15}: {1}".format(k, v))


def main():
    parser = ArgumentParser()
    subs = parser.add_subparsers(dest='cmd')

    setup_parser = subs.add_parser('setup')
    setup_parser.add_argument('username', help="Username associated with the \
                                                API key and account")
    setup_parser.add_argument('key', help='API key')
    setup_parser.add_argument('--http-proxy', '--http', default='',
                              help='proxy to use for http requests')
    setup_parser.add_argument('--https-proxy', '--https', default='',
                              help='proxy to use for https requests')

    show_parser = subs.add_parser('show',
                                  help='show current API configuration')
    args = parser.parse_args()

    if args.cmd == 'show':
        config = Config()
        show_config(config)
    elif args.cmd == 'setup':
        config_options = {}
        config_options['api_key'] = args.key
        config_options['username'] = args.username
        config_options['http_proxy'] = args.http_proxy
        config_options['https_proxy'] = args.https_proxy
        config = Config(**config_options)
        show_config(config)


if __name__ == '__main__':
    main()
