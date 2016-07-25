#!/usr/bin/env python
"""PassiveTotal script to get the latest resolutions for the current day.

This script will use the passive DNS endpoint in order to get all resolutions
for a given query for the current day. Unique items will be printed to stdout.
"""

__author__ = 'Brandon Dixon (brandon@passivetotal.org)'
__version__ = '1.0.0'
__keywords__ = ['unique', 'new resolutions']
__requirements__ = ['passivetotal', 'requests']

import datetime
import sys
from passivetotal.libs.dns import DnsRequest

PT_USERNAME = "--YOUR-USERNAME--"
PT_API_KEY = "--YOUR-API-KEY--"


def main():
    """Perform a passive DNS lookup and save the output."""
    if len(sys.argv) <= 1:
        print("Usage: python show_latest <query>")
        sys.exit(1)

    query = sys.argv[1]
    current_day = datetime.datetime.now().strftime("%Y-%m-%d")
    client = DnsRequest(PT_USERNAME, PT_API_KEY)
    results = client.get_passive_dns(query=query, start=current_day)

    unique = list()
    for record in results.get('results', list()):
        resolve = record['resolve']
        if resolve in unique:
            continue
        unique.append(resolve)
        print resolve

if __name__ == "__main__":
    main()
