#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.api import Client
# exceptions
from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_FIELD_TYPE
# const
from passivetotal.common.const import SSL_VALID_FIELDS


class SslRequest(Client):

    """Client to interface with the SSL calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(SslRequest, self).__init__(*args, **kwargs)

    def get_ssl_certificate_details(self, **kwargs):
        """Get SSL certificate details based on query value.

        Reference: https://api.passivetotal.org/api/docs/#api-SSL_Certificates-GetSslCertificateQuery

        :param str query: SHA-1 or IP address
        :param str compact_record: Return the record in a compact format
        :return: SSL certificate details for the query
        """
        return self._get('ssl-certificate', '', **kwargs)

    def get_ssl_certificate_history(self, **kwargs):
        """Search SSL certificate history.

        Reference: https://api.passivetotal.org/api/docs/#api-SSL_Certificates-GetSslCertificateHistoryQuery

        :param str query: SHA-1 or IP address
        :param str compact_record: Return the record in a compact format
        :param str field: Field to run the query against
        :param str type: Type of search to conduct
        :return: SSL certificates records matching the query
        """
        return self._get('ssl-certificate', 'history', **kwargs)

    def search_ssl_certificate_by_field(self, **kwargs):
        """Search SSL certificate details based on query value and field.

        Reference: https://api.passivetotal.org/api/docs/#api-SSL_Certificates-GetSslCertificateSearchQueryField

        :param str query: Query value to use when making the request for data
        :param str compact_record: Return the record in a compact format
        :param str field: Field to run the query against
        :param str type: Type of search to conduct
        :return: SSL certificates matching the query
        """
        if 'field' not in kwargs:
            raise MISSING_FIELD("Field value is required.")
        if kwargs['field'] not in SSL_VALID_FIELDS:
            raise INVALID_FIELD_TYPE("Field must be one of the following: %s"
                                     % ', '.join(SSL_VALID_FIELDS))
        return self._get('ssl-certificate', 'search', **kwargs)

    def search_keyword(self, **kwargs):
        """Search for a keyword across SSL certificate data.

        Reference: https://api.passivetotal.org/api/docs/#api-SSL_Certificates-GetV2SslCertificateSearchQueryField

        :param str query: Keyword value to search for in the dataset
        :return: List of matching hits based on the keyword
        """
        return self._get('ssl-certificate', 'search', 'keyword', **kwargs)
