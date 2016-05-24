#!/usr/bin/env python

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

import sys

from argparse import ArgumentParser
from passivetotal.common.utilities import prune_args
from passivetotal.common.utilities import to_bool
from passivetotal.common.utilities import valid_date
from passivetotal.libs.attributes import AttributeRequest
from passivetotal.libs.actions import ActionsClient
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.ssl import SslRequest
from passivetotal.libs.whois import WhoisRequest
from passivetotal.response import Response


def call_dns(args):
    """Abstract call to DNS-based queries."""
    client = DnsRequest.from_config()
    pruned = prune_args(
        query=args.query,
        end=args.end,
        start=args.start,
        timeout=args.timeout,
        sources=args.sources
    )

    if args.unique:
        data = client.get_unique_resolutions(**pruned)
    else:
        data = client.get_passive_dns(**pruned)

    return data


def call_attribute(args):
    """Abstract call to attribute-based queries."""
    client = AttributeRequest.from_config()
    pruned = prune_args(
        query=args.query,
        type=args.type
    )

    if args.type == 'tracker':
        data = client.get_host_attribute_trackers(**pruned)
    else:
        data = client.get_host_attribute_components(**pruned)

    return data


def call_whois(args):
    """Abstract call to WHOIS-based queries."""
    client = WhoisRequest.from_config()
    pruned = prune_args(
        query=args.query,
        compact_record=args.compact,
        field=args.field
    )

    if not args.field:
        data = client.get_whois_details(**pruned)
    else:
        data = client.search_whois_by_field(**pruned)

    return data


def call_ssl(args):
    """Abstract call to SSL-based queries."""
    client = SslRequest.from_config()
    pruned = prune_args(
        query=args.query,
        compact_record=args.compact,
        field=args.field,
        type=args.type
    )

    valid_types = ['search', 'history']
    if args.type and args.type not in valid_types:
        raise ValueError("Invalid type specified.")

    if not args.type:
        data = client.get_ssl_certificate_details(**pruned)
    elif args.type == 'history':
        data = client.get_ssl_certificate_history(**pruned)
    elif args.type == 'search' and args.field:
        data = client.search_ssl_certificate_by_field(**pruned)
    else:
        raise ValueError("Field argument was missing from the call.")

    return data


def call_actions(args):
    """Abstract call to actions-based queries."""
    client = ActionsClient.from_config()
    pruned = prune_args(
        query=args.query,
        tags=args.tags,
        classification=args.classification,
        monitor=args.monitor,
        sinkhole=args.sinkhole,
        dynamic_dns=args.dynamic_dns,
        ever_compromised=args.ever_compromised,
        metadata=args.metadata
    )

    if args.tags:
        tag_values = [x.strip() for x in args.tags.split(',')]
        pruned['tags'] = tag_values
        if args.add_tags:
            data = client.add_tags(**pruned)
        elif args.remove_tags:
            data = client.remove_tags(**pruned)
        elif args.set_tags:
            data = client.set_tags(**pruned)
        else:
            raise ValueError("Tag action required.")

    if args.classification:
        data = client.set_classification_status(**pruned)

    if args.monitor:
        pruned['status'] = to_bool(args.monitor)
        data = client.set_monitor_status(**pruned)

    if args.sinkhole:
        pruned['status'] = to_bool(args.sinkhole)
        data = client.set_sinkhole_status(**pruned)

    if args.dynamic_dns:
        pruned['status'] = to_bool(args.dynamic_dns)
        data = client.set_dynamic_dns_status(**pruned)

    if args.ever_compromised:
        pruned['status'] = to_bool(args.ever_compromised)
        data = client.set_ever_compromised_status(**pruned)

    if args.metadata:
        data = client.get_metadata(**pruned)

    return data


def write_output(results, arguments):
    """Format data based on the type.

    :param results: Result data from one of the various calls
    :param arguments: Supplied arguments from the CLI
    :return: Formatted list of output data
    """
    if not arguments.format:
        arguments.format = 'json'
        data = Response.process(results)
    data = [getattr(data, arguments.format)]

    return data


def main():
    parser = ArgumentParser(description="PassiveTotal Command Line Client")
    subs = parser.add_subparsers(dest='cmd')

    pdns = subs.add_parser('pdns', help="Query passive DNS data")
    pdns.add_argument('--query', '-q', required=True,
                      help="Query for a domain, IP address or wildcard")
    pdns.add_argument('--sources', type=str, default=None,
                      help="CSV string of passive DNS sources", nargs='+')
    pdns.add_argument('--end', '-e', default=None, type=valid_date,
                      help="Filter records up to this end date (YYYY-MM-DD)")
    pdns.add_argument('--start', '-s', default=None, type=valid_date,
                      help="Filter records from this start date (YYYY-MM-DD)")
    pdns.add_argument('--timeout', '-t', default=3,
                      help="Timeout to use for passive DNS source queries")
    pdns.add_argument('--unique', action="store_true",
                      help="Use this to only get back unique resolutons")
    pdns.add_argument('--format', choices=['json', 'text', 'csv',
                                           'stix', 'table', 'xml'],
                      help="Format of the output from the query")

    whois = subs.add_parser('whois', help="Query WHOIS data")
    whois.add_argument('--query', '-q', required=True,
                       help="Query for a domain or IP address")
    whois.add_argument('--field', '-f', type=str, default=None,
                       help="Run a specific query against a WHOIS field")
    whois.add_argument('--compact', action="store_true",
                       help="Show WHOIS record in a compact way")
    whois.add_argument('--format', choices=['json', 'text', 'csv',
                                            'stix', 'table', 'xml'],
                       help="Format of the output from the query")

    ssl = subs.add_parser('ssl', help="Query SSL certificate data")
    ssl.add_argument('--query', '-q', required=True,
                     help="Query for an IP address or SHA-1")
    ssl.add_argument('--field', '-f', type=str, default=None,
                     help="Run a specific query against a certificate field")
    ssl.add_argument('--type', '-t', choices=['search', 'history'],
                     help="Perform a plain search or get history")
    ssl.add_argument('--compact', action="store_true",
                     help="Show SSL record in a compact way")
    ssl.add_argument('--format', choices=['json', 'text', 'csv',
                                          'stix', 'table', 'xml'],
                     help="Format of the output from the query")

    attribute = subs.add_parser('attribute', help="Query host attribute data")
    attribute.add_argument('--query', '-q', required=True,
                           help="Query for a domain or IP address")
    attribute.add_argument('--type', '-t', choices=['tracker', 'component'],
                           help="Query tracker data or component data",
                           required=True)
    attribute.add_argument('--format', choices=['json', 'csv', 'table', 'xml'],
                           help="Format of the output from the query")

    action = subs.add_parser('action', help="Query and input feedback")
    action.add_argument('--query', '-q', required=True,
                        help="Domain, IP address, Email, SSL certificate")
    action.add_argument('--metadata', action="store_true",
                        help="Get metadata associated with a query")
    action.add_argument('--tags', type=str, default=None,
                        help="Tag values to use in conjunction with an action")
    action.add_argument('--add-tags', action="store_true",
                        help="Add tag values")
    action.add_argument('--remove-tags', action="store_true",
                        help="Remove tag values")
    action.add_argument('--set-tags', action="store_true",
                        help="Set tag values")
    action.add_argument('--classification', choices=['malicious',
                        'non-malicious', 'suspicious', 'unknown'],
                        help="Classification to apply to the query")
    action.add_argument('--monitor', choices=['true', 'false'],
                        help="Read or write a monitor value")
    action.add_argument('--sinkhole', choices=['true', 'false'],
                        help="Read or write a sinkhole value")
    action.add_argument('--dynamic-dns', choices=['true', 'false'],
                        help="Read or write a dynamic DNS value")
    action.add_argument('--ever-compromised', choices=['true', 'false'],
                        help="Read or write a compromised value")
    action.add_argument('--json', '-j', action="store_true",
                        help="Output as JSON")

    args, unknown = parser.parse_known_args()
    data = None

    try:
        if args.cmd == 'pdns':
            data = call_dns(args)
        elif args.cmd == 'whois':
            data = call_whois(args)
        elif args.cmd == 'ssl':
            data = call_ssl(args)
        elif args.cmd == 'action':
            data = call_actions(args)
        elif args.cmd == 'attribute':
            data = call_attribute(args)
        else:
            parser.print_usage()
            sys.exit(1)

    except ValueError as e:
        parser.print_usage()
        sys.stderr.write('{}\n'.format(str(e)))
        sys.exit(1)

    output = write_output(data, args)
    for item in output:
        print(item + "\n")

if __name__ == '__main__':
    main()
