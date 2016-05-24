#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.api import Client


class EnrichmentRequest(Client):

    """Client to interface with the enrichment calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(EnrichmentRequest, self).__init__(*args, **kwargs)

    def get_enrichment(self, **kwargs):
        """Get enrichment data for a value.

        Reference: https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentQuery

        :param query: Value to enrich
        :return: Dict of results
        """
        return self._get('enrichment', '', **kwargs)

    def get_bulk_enrichment(self, **kwargs):
        """Get bulk enrichment data for a value.

        Reference: https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentBulkQuery

        :param query: Value to enrich
        :return: Dict of results
        """
        data = {'query': kwargs['query']}
        return self._get_special('enrichment', 'bulk', '', data)

    def get_osint(self, **kwargs):
        """Get OSINT data for a value.

        Reference: https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentOsintQuery

        :param query: Value to search for in OSINT
        :return: Dict of results
        """
        return self._get('enrichment', 'osint', **kwargs)

    def get_bulk_osint(self, **kwargs):
        """Get bulk OSINT data for a value.

        Reference: https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentBulkOsintQuery

        :param query: Value to search for in OSINT
        :return: Dict of results
        """
        data = {'query': kwargs['query']}
        return self._get_special('enrichment', 'bulk', 'osint', data)

    def get_malware(self, **kwargs):
        """Get malware data for a value.

        Reference: https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentMalwareQuery

        :param query: Value to search for in malware
        :return: Dict of results
        """
        return self._get('enrichment', 'malware', **kwargs)

    def get_bulk_malware(self, **kwargs):
        """Get bulk malware data for a value.

        Reference: https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentBulkMalwareQuery

        :param query: Value to search for in OSINT
        :return: Dict of results
        """
        data = {'query': kwargs['query']}
        return self._get_special('enrichment', 'bulk', 'malware', data)

    def get_subdomains(self, **kwargs):
        """Get listing of subdomains for a given query.

        Reference: https://api.passivetotal.org/api/docs/#api-Enrichment-GetV2EnrichmentSubdomains
        """
        return self._get('enrichment', 'subdomains', **kwargs)
