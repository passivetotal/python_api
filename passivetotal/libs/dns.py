"""PassiveTotal API Interface."""
from passivetotal.api import Client
from passivetotal.response import Response
from passivetotal.common import utilities
from passivetotal.common.const import DNS_APPROVED_FIELDS as approved_fields

__author__ = 'RiskIQ'
__version__ = '1.2.0'


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


class DnsResponse(Response):
    @property
    def csv(self):
        data = []
        for record in self._results['results']:
            data.append([record.get(i) for i in approved_fields])
        return utilities.to_csv(approved_fields, data)
