#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.api import Client
# exceptions
from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_FIELD_TYPE
# const
from passivetotal.common.const import WHOIS_VALID_FIELDS


class WhoisRequest(Client):

    """Client to interface with the WHOIS calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Inherit from the base class."""
        super(WhoisRequest, self).__init__(*args, **kwargs)

    def get_whois_details(self, **kwargs):
        """Get WHOIS details based on query value.

        Reference: https://api.passivetotal.org/api/docs/#api-WHOIS-GetV2WhoisQuery

        :param str query: Query value to use when making the request for data
        :param str compact_record: Return the record in a compact format
        :return: WHOIS details for the query
        """
        return self._get('whois', '', **kwargs)

    def search_whois_by_field(self, **kwargs):
        """Search WHOIS details based on query value and field.

        Reference: https://api.passivetotal.org/api/docs/#api-WHOIS-GetV2WhoisSearchQueryField

        :param str query: Query value to use when making the request for data
        :param str compact_record: Return the record in a compact format
        :param str field: Field to run the query against
        :return: WHOIS records matching the query
        """
        if 'field' not in kwargs:
            raise MISSING_FIELD("Field value is required.")
        if kwargs['field'] not in WHOIS_VALID_FIELDS:
            raise INVALID_FIELD_TYPE("Field must be one of the following: %s"
                                     % ', '.join(WHOIS_VALID_FIELDS))
        return self._get('whois', 'search', **kwargs)

    def search_keyword(self, **kwargs):
        """Search for a keyword across WHOIS data.

        Reference: https://api.passivetotal.org/api/docs/#api-WHOIS-GetV2WhoisSearchKeywordQuery

        :param str query: Keyword value to search for in the dataset
        :return: List of matching hits based on the keyword
        """
        return self._get('whois', 'search', 'keyword', **kwargs)

