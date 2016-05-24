#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.api import Client


class DnsRequest(Client):

    """Client to interface with the DNS calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Inherit from the base class."""
        super(DnsRequest, self).__init__(*args, **kwargs)

    def get_passive_dns(self, **kwargs):
        """Get passive DNS data based on a query value.

        Reference: https://api.passivetotal.org/api/docs/#api-DNS-GetDnsPassiveQuery

        :param str query: Query value to use when making the request for data
        :param str start: Starting period for record filtering
        :param str end: Ending period for record filtering
        :param int timeout: Timeout to apply to source queries
        :param list sources: List of sources to use for the query
        :return: List of passive DNS results
        """
        return self._get('dns', 'passive', **kwargs)

    def get_unique_resolutions(self, **kwargs):
        """Get unique resolutions from passive DNS.

        Reference: https://api.passivetotal.org/api/docs/#api-DNS-GetDnsPassiveUniqueQuery

        :param str query: Query value to use when making the request for data
        :param str start: Starting period for record filtering
        :param str end: Ending period for record filtering
        :param int timeout: Timeout to apply to source queries
        :param list sources: List of sources to use for the query
        :return: List of passive DNS unique resolutions
        """
        return self._get('dns', 'passive', 'unique', **kwargs)

    def search_keyword(self, **kwargs):
        """Search for a keyword across passive DNS data.

        Reference: https://api.passivetotal.org/api/docs/#api-DNS-GetV2DnsSearchKeywordQuery

        :param str query: Keyword value to search for in the dataset
        :return: List of matching hits based on the keyword
        """
        return self._get('dns', 'search', 'keyword', **kwargs)