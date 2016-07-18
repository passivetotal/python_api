#!/usr/bin/env python
"""Perform a keyword search across passive DNS, WHOIS and SSL certificates

PassiveTotal provides a keyword search on several of its datasets that will
attempt to match the query provided by the user. Individual searches can be
conducted using the alternative search interface for each data type.

Note: Passive DNS keyword searches are not position independent and are only
supported as prefix or suffix. Supported methods would appear as follows:
- <keyword>.*
- *.<keyword>

Both WHOIS and SSL certificates will have keywords applied to all alpha-based
fields within the record. Keyword API documentation can be found here:
- DNS (https://api.passivetotal.org/api/docs/#api-DNS-GetV2DnsSearchKeywordQuery)
- WHOIS (https://api.passivetotal.org/api/docs/#api-WHOIS-GetV2WhoisSearchKeywordQuery)
- SSL (https://api.passivetotal.org/api/docs/#api-SSL_Certificates-GetV2SslCertificateSearchQueryField)
"""
__author__ = 'Brandon Dixon (brandon@passivetotal.org)'
__version__ = '1.0.0'
__description__ = "Search passive DNS, WHOIS and SSL certificates based on keywords"
__keywords__ = ['search', 'keywords', 'analysis']

import sys
import pkg_resources
import multiprocessing

#username = "--YOUR-USERNAME--"
#api_key = "--YOUR-API-KEY--"
username = "brandon@passivetotal.org"
api_key = "af62207054be38875f1566c21122e69d52c69ef680bf22d738a71d0a08a413db"


def _generate_request_instance(request_type):
    """Automatically generate a request instance to use.
    In the end, this saves us from having to load each request class in a
    explicit way. Loading via a string is helpful to reduce the code per
    call.
    """
    class_lookup = {'dns': 'DnsRequest', 'whois': 'WhoisRequest',
                    'ssl': 'SslRequest', 'enrichment': 'EnrichmentRequest',
                    'attributes': 'AttributeRequest'}
    class_name = class_lookup[request_type]
    mod = __import__('passivetotal.libs.%s' % request_type,
                     fromlist=[class_name])
    loaded = getattr(mod, class_name)
    authenticated = loaded(username, api_key)

    return authenticated


def _search(caller, query):
    """Execute a search with a loaded request instance."""
    client = _generate_request_instance(caller)
    response = client.search_keyword(query=query)
    if 'error' in response:
        err = response['error']
        formatted = "[!] %s: %s" % (err['message'], err['developer_message'])
        raise Exception(formatted)
    response[caller + '_results'] = response.pop('results', list())
    response.pop('queryValue', None)
    return response


def run_searches(query):
    """Use multiprocessing to issue each request at the same time."""
    reqs = ['dns', 'whois', 'ssl']
    pool = multiprocessing.Pool()
    tmp = [pool.apply_async(_search, args=(x, query,)) for x in reqs]
    results = dict()
    [results.update(r.get()) for r in tmp]

    return results

if __name__ == "__main__":
    pt_version = pkg_resources.get_distribution("passivetotal").version
    if int(pt_version.split('.')[2]) < 18:
        print("[!] PassiveTotal library is out of date. Please run 'pip install passivetotal --upgrade' to use this tool.")
        sys.exit(1)
    if len(sys.argv) < 2:
        print("Usage: python keyword_search.py <query-value> [csv|table]")
    if username[0] == '-' or api_key[0] == '-':
        print("[!] Edit this file to include your username and API key")

    query = sys.argv[1]
    if len(sys.argv) > 2:
        output = sys.argv.pop(2)
    else:
        output = 'csv'

    headers = ["Finding", "Dataset", "Type", "Location"]
    results = run_searches(query)

    rows = list()
    for key, value in results.iteritems():
        dataset = key.split('_')[0]
        for hit in value:
            rows.append([hit['focusPoint'], dataset,
                         hit['matchType'], hit['fieldMatch']])

    if output == 'csv':
        print(','.join(headers))
        for row in rows:
            print(','.join(row))
    else:
        from tabulate import tabulate
        print(tabulate(rows, headers))
