#!/usr/bin/env python
"""Quickly find related domains based on WHOIS data.

Use PassiveTotal's WHOIS repository to find related domains based on the fields
within the record.
"""
__author__ = 'Brandon Dixon (brandon@passivetotal.org)'
__version__ = '1.0.0'
__description__ = "Search WHOIS information by field and query value"
__keywords__ = ['search', 'whois', 'analysis']

import sys
from passivetotal.libs.whois import WhoisRequest

if len(sys.argv) != 3:
    print("Usage: python whois_search.py <field> <query-value>")

valid_types = ['domain', 'email', 'name',
               'organization', 'address', 'phone', 'nameserver']

query_type = sys.argv[1]
query_value = sys.argv[2]

if query_type not in valid_types:
    print("[!] ERROR: Query type must be one of the following:\n\t%s" % (', '.join(valid_types)))

client = WhoisRequest.from_config()
response = client.search_whois_by_field(field=query_type, query=query_value)
for item in response.get('results', []):
    domain = item.get('domain', None)
    if domain:
        print(domain, item.get('registered'), item.get('registryUpdatedAt'), item.get('expiresAt'))
