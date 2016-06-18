#!/usr/bin/env python
"""Use host pairs to surface tagged parents or children.

This script will take an original query with direction in order to surface
hosts related through web crawls that have been tagged.
"""
__author__ = 'Brandon Dixon (brandon@passivetotal.org)'
__version__ = '1.0.0'
__description__ = ""
__keywords__ = ['crawling', 'host pairs', 'analysis']

import sys

from passivetotal.libs.attributes import AttributeRequest
from passivetotal.libs.enrichment import EnrichmentRequest


def show_tagged(direction, enriched):
    for host, data in enriched.get("results", {}).items():
        if len(data['tags']) == 0:
            continue
        print(data['queryValue'], ','.join(data['tags']))

query = sys.argv[1]
direction = sys.argv[2]
result_key = {'parents': 'parent', 'children': 'child'}

if len(sys.argv) != 3:
    print("Usage: python host_pair_sentinel.py <query> <parents|children>")
    sys.exit(1)
if direction not in ['children', 'parents']:
    print("[!] Direction must be 'children' or 'parents' to work")
    sys.exit(1)

client = AttributeRequest.from_config()
matches = client.get_host_attribute_pairs(query=query, direction=direction)
hostnames = [x[result_key[direction]] for x in matches.get("results", list())]

client = EnrichmentRequest.from_config()
enriched = client.get_bulk_enrichment(query=hostnames)
show_tagged(direction, enriched)
