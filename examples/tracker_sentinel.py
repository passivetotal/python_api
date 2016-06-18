#!/usr/bin/env python
"""Automate crawling tracker codes based on inital query.

The best use of this script is to feed it a good domain in order to find other
web properties making use of the same tracking codes. While it does not always
reveal malicious activity, it does seem to be good at surfacing phishing pages.

Query flow:
1) Take in a domain or IP
2) Identify all tracking codes associated with the query
3) Search for other sites not matching the original query using any codes
4) Construct a table output with data for easy consumption
"""
__author__ = 'Brandon Dixon (brandon@passivetotal.org)'
__version__ = '1.0.0'
__description__ = "Surface related entities based on tracking codes"
__keywords__ = ['trackers', 'phishing', 'crimeware', 'analysis']

import sys
from tabulate import tabulate
from passivetotal.libs.attributes import AttributeRequest

query = sys.argv[1]
client = AttributeRequest.from_config()
# client.set_debug(True)
processed_values = list()


def surface_values(item):
    """Identify items that could be interesting."""
    if item.get('attributeValue') in processed_values:
        return {}

    children = client.search_trackers(
        query=item.get('attributeValue'),
        type=item.get('attributeType')
    )

    interesting = dict()
    for child in children.get('results', []):
        if child.get('hostname').endswith(query):
            continue
        interesting[child.get('hostname')] = child.get('everBlacklisted')
    processed_values.append(item.get('attributeValue'))
    return interesting


def main():
    """Take the inital query and surface anything strange."""
    all_records = list()
    initial_seed = client.get_host_attribute_trackers(query=query)
    for item in initial_seed.get('results', []):
        for hostname, blacklisted in surface_values(item).items():
            tmp = [item.get('hostname'), item.get('attributeType'),
                   item.get('attributeValue'), item.get('firstSeen'),
                   item.get('lastSeen'), hostname, str(blacklisted)]
            all_records.append(tmp)

    headers = ['Host', 'Attribute', 'Value', 'First Seen', 'Last Seen',
               'Suspect', 'Ever Blacklisted']

    print(tabulate(all_records, headers))

if __name__ == "__main__":
    main()
