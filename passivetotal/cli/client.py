#!/usr/bin/env python
import sys
from argparse import ArgumentParser
from datetime import datetime, timezone, timedelta
from passivetotal.common.utilities import prune_args
from passivetotal.common.utilities import to_bool
from passivetotal.common.utilities import valid_date
from passivetotal.libs.attributes import AttributeRequest, AttributeResponse
from passivetotal.libs.actions import ActionsClient, ActionsResponse
from passivetotal.libs.artifacts import ArtifactsRequest, ArtifactsResponse
from passivetotal.libs.dns import DnsRequest, DnsResponse
from passivetotal.libs.ssl import SslRequest, SSLResponse, SSLHistoryResponse
from passivetotal.libs.whois import WhoisRequest, WhoisResponse
from passivetotal.libs.articles import ArticlesRequest, ArticlesResponse, ArticlesIndicatorResponse
from passivetotal.libs.enrichment import EnrichmentRequest
from passivetotal.libs.cards import CardsRequest, CardsResponse
from passivetotal.libs.cookies import CookiesRequest, CookiesResponse
from passivetotal.libs.services import ServicesRequest, ServicesResponse
from passivetotal.libs.projects import ProjectsRequest, ProjectsResponse
from passivetotal.response import Response

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

DEFAULT_ARTICLE_DAYS_BACK = 7


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
        data = DnsResponse.process(client.get_unique_resolutions(**pruned))
    else:
        data = DnsResponse.process(client.get_passive_dns(**pruned))

    return data


def call_attribute(args):
    """Abstract call to attribute-based queries."""
    client = AttributeRequest.from_config()
    pruned = prune_args(
        query=args.query,
    )

    if args.type == 'tracker':
        data = AttributeResponse.process(
            client.get_host_attribute_trackers(**pruned)
        )
    elif args.type == 'cookie':
        data = AttributeResponse.process(
            client.get_host_attribute_cookies(**pruned)
        )
    else:
        data = AttributeResponse.process(
            client.get_host_attribute_components(**pruned)
        )

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
        data = WhoisResponse.process(
            client.get_whois_details(**pruned)
        )
    else:
        data = WhoisResponse.process(
            client.search_whois_by_field(**pruned)
        )

    return data


def call_ssl(args):
    """Abstract call to SSL-based queries."""
    client = SslRequest.from_config()
    pruned = prune_args(
        query=args.query,
        compact_record=args.compact,
        field=args.field,
    )

    valid_types = ['search', 'history']
    if args.type and args.type not in valid_types:
        raise ValueError("Invalid type specified.")

    if not args.type:
        data = SSLResponse.process(
            {'results': [client.get_ssl_certificate_details(**pruned)]}
        )
    elif args.type == 'history':
        data = SSLHistoryResponse.process(
            client.get_ssl_certificate_history(**pruned)
        )
    elif args.type == 'search' and args.field:
        data = SSLResponse.process(
            client.search_ssl_certificate_by_field(**pruned)
        )
    else:
        raise ValueError("Field argument was missing from the call.")

    return data


def call_osint(args):
    client = EnrichmentRequest.from_config()
    return client.get_osint(query=args.query)


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
    data = {}
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

    if args.search_tags:
        data = client.search_tags(**pruned)

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

    return ActionsResponse.process(data)

def call_articles(args):
    client = ArticlesRequest.from_config()
    if args.query == 'indicators':
        pruned = prune_args(
            articleGuid = args.guid,
            startDate = args.startdate
        )
        return ArticlesIndicatorResponse.process(
            client.get_indicators(**pruned)
        )
    elif args.query == 'details':
        return ArticlesResponse.process(
            client.get_details(args.guid)
        )
    elif args.query == 'articles':
        pruned = prune_args(
            page = args.page,
            order = args.order
        )
        return ArticlesResponse.process(
            client.get_articles(**pruned)
        )

def call_artifacts(args):
    client = ArtifactsRequest.from_config()
    pruned = prune_args(
        artifact = args.id,
        project = args.project,
        owner = args.owner,
        creator = args.creator,
        organization = args.organization,
        query = args.query,
        type = args.type,
    )
    return ArtifactsResponse.process(
        client.get_artifacts(**pruned)
    )

def call_summary(args):
    client = CardsRequest.from_config()
    data = CardsResponse.process(
        client.get_summary(query=args.query)
    )
    return data

def call_cookies(args):
    client = CookiesRequest.from_config()
    meth = 'get_{0.object}_{0.search}'.format(args)
    pruned = prune_args(
        page = args.page,
        sort = args.sort,
        order = args.order,
    )
    data = CookiesResponse.process(
        getattr(client, meth)(args.query, **pruned)
    )
    return data

def call_services(args):
    client = ServicesRequest.from_config()
    data = ServicesResponse.process(
        client.get_services(query=args.ip)
    )
    return data

def call_projects(args):
    client = ProjectsRequest.from_config()
    pruned = prune_args(
        project = args.id,
        owner = args.owner,
        creator = args.creator,
        organization = args.organization,
        visibility = args.visibility,
        featured = args.featured,
        name = args.name,
        description = args.description,
        tags = args.tags
    )
    if 'tags' in pruned:
        pruned['tags'] = pruned['tags'].split(',')
    if args.projects_cmd not in ['search','create']:
        if not args.id:
            raise ValueError("project id (--id) is required for this action")
    if args.projects_cmd == 'search':
        response = client.get_projects(**pruned)
    elif args.projects_cmd == 'create':
        if not args.name:
            raise ValueError("Name argument is required when creating a project")
        del(pruned['name'])
        response = client.create_project(name=args.name, **pruned)
    elif args.projects_cmd == 'update':
        response = client.update_project(guid=args.id, **pruned)
    elif args.projects_cmd == 'delete':
        response = client.delete_project(guid=args.id)
    elif args.projects_cmd in ['add_tags','set_tags','remove_tags']:
        if not 'tags' in pruned:
            raise ValueError("tag argument is required for tag actions")
        response = getattr(client, args.projects_cmd)(args.id, pruned['tags'])
    data = ProjectsResponse.process(response)
    return data


def write_output(results, arguments):
    """Format data based on the type.

    :param results: Result data from one of the various calls
    :param arguments: Supplied arguments from the CLI
    :return: Formatted list of output data
    """
    if not arguments.format:
        arguments.format = 'json'
    data = [getattr(results, arguments.format)]

    return data

def days_back(days):
    """Return a formatted date from several days in the past.

    :param days: number of days back
    :return: Date in YYYY-MM-DD format
    """
    past = datetime.now(timezone.utc) - timedelta(days=days)
    return past.date().isoformat() + ' 00:00:00'


def main():
    parser = ArgumentParser(
        description="PassiveTotal Command Line Client",
        prog='passivetotal')
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
    pdns.add_argument('--format', choices=['json', 'csv'],
                      help="Format of the output from the query")

    whois = subs.add_parser('whois', help="Query WHOIS data")
    whois.add_argument('--query', '-q', required=True,
                       help="Query for a domain or IP address")
    whois.add_argument('--field', '-f', type=str, default=None,
                       help="Run a specific query against a WHOIS field")
    whois.add_argument('--compact', action="store_true",
                       help="Show WHOIS record in a compact way")
    whois.add_argument('--format', choices=['json'],
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
    ssl.add_argument('--format', choices=['json', 'csv'],
                     help="Format of the output from the query")

    attribute = subs.add_parser('attribute', help="Query host attribute data")
    attribute.add_argument('--query', '-q', required=True,
                           help="Query for a domain or IP address")
    attribute.add_argument('--type', '-t', choices=['tracker', 'component', 'cookie'],
                           help="Query tracker data or component data",
                           required=True)
    attribute.add_argument('--format', choices=['json', 'csv'],
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
    action.add_argument('--search-tags', action="store_true",
                        help="Retrieve artifacts for a given tag")
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
    action.add_argument('--format', choices=['json'], default='json',
                        help="Format of the output from the query")

    osint = subs.add_parser('osint', help="Query OSINT data")
    osint.add_argument('--query', '-q', required=True,
                       help="Query for a domain or IP address")
    osint.add_argument('--format', choices=['json'],
                       help="Format of the output from the query")

    articles = subs.add_parser('articles', help="Query Articles data")
    articles.add_argument('--query', '-q', required=False, default='articles',
                        choices=['articles','indicators','details'],
                        help="Articles API query type.")
    articles.add_argument('--guid', default=None,
                        help="GUID of the article (optional)")
    articles.add_argument('--page', default=None,
                        help="Page of the article list (optional)")
    articles.add_argument('--order', default=None,
                        choices=['asc','desc'],
                        help="Article sort order (optional)")
    articles.add_argument('--startdate',
                        default=days_back(DEFAULT_ARTICLE_DAYS_BACK),
                        help="Starting date for indicator list in YYYY-MM-DD format, defaults to 7 days ago")
    articles.add_argument('--format', choices=['json', 'csv'],
                        help="Format of the output from the query")

    artifacts = subs.add_parser('artifacts', help="Query Artifacts data")
    artifacts.add_argument('--id',
                        help="Filter by artifact ID")
    artifacts.add_argument('--project',
                        help="Filter by project ID")
    artifacts.add_argument('--owner',
                        help="Filter by owner email or org ID")
    artifacts.add_argument('--creator',
                        help="Filter by creator")
    artifacts.add_argument('--organization',
                        help="Filter by organization")
    artifacts.add_argument('--query',
                        help="Filter by query")
    artifacts.add_argument('--type',
                        help="Filter by artifact type")
    artifacts.add_argument('--format', choices=['json'], default='json',
                        help="Format of the output from the query")

    summary = subs.add_parser('summary', help="Query summary data")
    summary.add_argument('--query', '-q', required=True,
                        help="Domain or IP to get summary data")
    summary.add_argument('--format', choices=['json'], default='json',
                        help="Format of the output from the query")

    cookies = subs.add_parser('cookies', help="Query cookies data")
    cookies.add_argument('--query', '-q', required=True,
                        help="Domain or cookie name")
    cookies_object_group = cookies.add_mutually_exclusive_group(required=True)
    cookies_object_group.add_argument('--addresses', dest='object', 
                        action='store_const', const='addresses',
                        help="Get cookie addresses")
    cookies_object_group.add_argument('--hosts', dest='object',
                        action='store_const', const='hosts',
                        help="Get cookie hostnames")
    cookies_search_group = cookies.add_mutually_exclusive_group(required=True)
    cookies_search_group.add_argument('--by-domain', dest='search',
                        action='store_const', const='by_domain',
                        help='Search cookies by cookie domain')
    cookies_search_group.add_argument('--by-name', dest='search',
                        action='store_const', const='by_name',
                        help='Search cookies by cookie hosts')
    cookies.add_argument('--page', default=None,
                        help="Page of the cookies results (optional)")
    cookies.add_argument('--order', default=None,
                        choices=['asc','desc'],
                        help="Cookies results sort order (optional)")
    cookies.add_argument('--sort', default=None,
                        choices=['lastSeen','firstSeen'],
                        help="Sort cookies results by date (optional)")
    cookies.add_argument('--format', choices=['json'], default='json',
                        help="Format of the output from the query")

    services = subs.add_parser('services', help="Query services data")
    services.add_argument('--ip', required=True,
                        help="IP address to search")
    services.add_argument('--format', choices=['json'], default='json',
                        help="Format of the output from the query")

    projects = subs.add_parser('projects', help="Query projects API")
    projects_cmd = projects.add_mutually_exclusive_group(required=True)
    projects_cmd.add_argument('--search', dest='projects_cmd', action='store_const', const='search',
                        help="Search all projects")
    projects_cmd.add_argument('--create', dest='projects_cmd', action='store_const', const='create',
                        help="Create a project")
    projects_cmd.add_argument('--update', dest='projects_cmd', action='store_const', const='update',
                        help="Update an existing projects")
    projects_cmd.add_argument('--delete', dest='projects_cmd', action='store_const', const='delete',
                        help="Delete a project")
    projects_cmd.add_argument('--add-tags', dest='projects_cmd', action='store_const', const='add_tags',
                        help="Add tags to a project")
    projects_cmd.add_argument('--set-tags', dest='projects_cmd', action='store_const', const='set_tags',
                        help="Set tags on a project (removing any not listed)")
    projects_cmd.add_argument('--remove-tags', dest='projects_cmd', action='store_const', const='remove_tags',
                        help="Remove one or more tags from a project")
    projects.add_argument('--id',
                        help="Filter searches or scope commands by project GUID")
    projects.add_argument('--owner',
                        help="Filter searches by owner email or org id")
    projects.add_argument('--creator',
                        help="Filter searches by creator email")
    projects.add_argument('--organization',
                        help="Filter searches by organization")
    projects.add_argument('--visibility', choices=['public','private','analyst'],
                        help="Filter searches or set project attribute by visibility")
    projects.add_argument('--featured', action='store_true', default=False,
                        help="Filter searches or set project attribute by featured status")
    projects.add_argument('--name',
                        help="Project name (required when creating or updating)")
    projects.add_argument('--description',
                        help="Project description (when creating or updating)")
    projects.add_argument('--tags',
                        help="Comma-separated list of tags")
    projects.add_argument('--format', choices=['json'], default='json',
                        help="Format of the output from the query")


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
        elif args.cmd == 'osint':
            data = call_osint(args)
        elif args.cmd == 'articles':
            data = call_articles(args)
        elif args.cmd == 'artifacts':
            data = call_artifacts(args)
        elif args.cmd == 'summary':
            data = call_summary(args)
        elif args.cmd == 'cookies':
            data = call_cookies(args)
        elif args.cmd == 'services':
            data = call_services(args)
        elif args.cmd == 'projects':
            data = call_projects(args)
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
