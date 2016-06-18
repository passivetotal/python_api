#!/usr/bin/env python
"""Take a starting point and surface tagged items

There are times when it's difficult to tell which items have been tagged as
something malicious or suspicious. This script will take an initial starting
point and print out any tagged items along with their tags.
"""
__author__ = 'Brandon Dixon (brandon@passivetotal.org)'
__version__ = '1.0.0'
__description__ = "Surface tagged items from a passive DNS query"
__keywords__ = ['pdns', 'tags', 'triage', 'analysis']

import sys
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.enrichment import EnrichmentRequest

query = sys.argv[1]
client = DnsRequest.from_config()
enricher = EnrichmentRequest.from_config()


def main():
    """Take an initial seed and identify OSINT tags."""
    initial_seed = client.get_unique_resolutions(query=query)
    all_records = initial_seed.get('results', list())
    all_records += query
    for item in all_records:
        tmp = enricher.get_enrichment(query=item)
        tags = tmp.get('tags', list())
        if len(tags) > 0:
            print("%s - %s" % (item, ', '.join(tags)))

if __name__ == "__main__":
    main()
