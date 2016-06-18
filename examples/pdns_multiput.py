#!/usr/bin/env python
"""Demonstrate how PassiveTotal results can easily output in many forms.

The new PassiveTotal python libraries provide a number of different output
formats for the results. This simple tool lets a user perform a passive DNS
lookup using our system and then saves the results in a number of useful
outputs for later processing.
"""
__author__ = 'Brandon Dixon (brandon@passivetotal.org)'
__version__ = '1.0.0'
__description__ = "Convert passive DNS results into multiple formats"
__keywords__ = ['formats', 'pdns', 'sharing', 'analysis']

import sys
# import the DNS libraries from PassiveTotal
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.dns import DnsResponse


def main():
    """Perform a passive DNS lookup and save the output."""
    if len(sys.argv) <= 1:
        print("Usage: python pdns_multiput <query>")
        sys.exit(1)

    query = sys.argv[1]
    output_formats = ['json', 'xml', 'stix', 'csv', 'table']
    client = DnsRequest.from_config()
    raw_results = client.get_passive_dns(query=query)
    pdns_results = DnsResponse(raw_results)
    for format_type in output_formats:
        save_location = "/tmp/%s.pdns.%s" % (query, format_type)
        tmp = open(save_location, "w")
        tmp.write(getattr(pdns_results, format_type))
        tmp.close()
    print("Saved results inside of /tmp/%s" % (query))

if __name__ == "__main__":
    main()
