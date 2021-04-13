#!/usr/bin/env python

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.config import Config
from argparse import ArgumentParser
import getpass 


def show_config(config, plaintext=False):
    print("\nCurrent Configuration:\n")
    lines = {
        'username': config.config['username'],
    }
    secret = config.config['api_key']
    if plaintext:
        lines['secret'] = secret
    else:
        lines['secret'] = secret[0:4] + ('*' * (len(secret)-8)) + secret[-4:]
    lines.update(
        { k: config.config[k] for k in sorted(config.config.keys()) if k not in ['username','api_key']}
    )
    for k, v in lines.items():
        print("  {0:15}: {1}".format(k, v))


def main():
    parser = ArgumentParser(prog='pt-config')
    subs = parser.add_subparsers(dest='cmd')

    setup_parser = subs.add_parser('setup',
        help='Setup PassiveTotal API credentials and connection params.')
    setup_parser.add_argument('username',
        help='Username, API key or email address associated with the API account.')
    setup_parser.add_argument('-s', '--secret', default=None,
        help='Secret key associated with the API account; leave blank for interactive prompt')
    setup_parser.add_argument('--http-proxy', '--http', default='',
        help='Proxy to use for http requests')
    setup_parser.add_argument('--https-proxy', '--https', default='',
        help='Proxy to use for https requests')

    show_parser = subs.add_parser('show',
        help='Show current PassiveTotal API configuration.')
    show_parser.add_argument('--plaintext', action='store_true', default=False,
        help='Show API secrets in plaintext.')
    
    args = parser.parse_args()

    if args.cmd == 'show':
        config = Config()
        show_config(config, args.plaintext)
    elif args.cmd == 'setup':
        config_options = { }
        if not args.secret:
            config_options['api_key'] = getpass.getpass(prompt='API secret: ')
        else:
            config_options['api_key'] = args.secret
        config_options['username'] = args.username
        config_options['http_proxy'] = args.http_proxy
        config_options['https_proxy'] = args.https_proxy
        config = Config(**config_options)
        show_config(config)
    else:
        parser.print_usage()


if __name__ == '__main__':
    main()
