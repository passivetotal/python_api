#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from future.utils import iteritems
from tabulate import tabulate
from passivetotal.api import Client
from passivetotal.response import Response
# exceptions
from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_FIELD_TYPE
# const
from passivetotal.common.const import SSL_VALID_FIELDS
from passivetotal.common.exceptions import INVALID_VALUE_TYPE


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


class SslResponse(Response):

    """Result object to ease interaction with data."""

    def __init__(self, *args, **kwargs):
        """Inherit from the base class."""
        super(SslResponse, self).__init__(*args, **kwargs)

    @property
    def csv(self):
        """Output data as CSV.

        :return: String of formatted data
        """
        output = ''
        output += ','.join(sorted(SSL_VALID_FIELDS)) + "\n"
        content = list()
        for detail in sorted(SSL_VALID_FIELDS):
            tmp = self._results.get(detail, '')
            if not tmp:
                tmp = ''
            content.append(tmp)
        output += ','.join(content)
        output = output.strip()

        return output

    @property
    def table(self):
        """Output data as table.

        :return: Table of formatted data
        """
        output = ''
        records = list()
        for detail in sorted(SSL_VALID_FIELDS):
            tmp = self._results.get(detail, '')
            if not tmp:
                tmp = ''
            records.append([detail, tmp])
        output = tabulate(records, ['Field', 'Value'])

        return output

    @property
    def text(self):
        """Output data as text.

        Data shown in the text output is not full-featured and contains only
        content deemed to be most useful to the end-user. For full data output,
        use JSON or XML outputs.

        :return: String of formatted data
        """
        output = ''
        output += "[*] SHA-1: %s\n" % self.sha1
        output += "[*] Fingerprint: %s\n" % self.fingerprint
        output += "[*] SSL Version: %s\n" % self.sslVersion
        output += "[*] Issue Date: %s\n" % self.issueDate
        output += "[*] Expiration Date: %s\n" % self.expirationDate
        output += "[*] Subject Details:\n"
        for item in SSL_VALID_FIELDS:
            if not item.startswith('subject_'):
                continue
            output += "\t%s: %s\n" % (
                item.replace('subject_', ''),
                self._results.get(item, '')
            )
        output += "[*] Issuer Details:\n"
        for item in SSL_VALID_FIELDS:
            if not item.startswith('issuer_'):
                continue
            output += "\t%s: %s\n" % (
                item.replace('issuer_', ''),
                self._results.get(item, '')
            )
        output = output.strip()

        return output


class SslSearchResponse(object):

    """Process records from search response."""

    def __init__(self, results):
        """Load all the records into SSL certificate responses."""
        self._results = results
        self._records = list()
        for item in self._results.get('results', []):
            self._records.append(SslResponse(item))

    def get_records(self):
        return self._records

    @property
    def records(self):
        return self._records


class HistoryRecord(object):

    """Provide some basic helpers for the SSL certificate records."""

    def __init__(self, record):
        """Initialize the class.

        :param dict record: Record to load into the class
        """
        if type(record) != dict:
            raise INVALID_VALUE_TYPE("Record must be of type dict")
        self._record = record
        self._boost_properties()

    def _boost_properties(self):
        """Make first-class keys attributes of the object."""
        for key, value in iteritems(self._record):
            setattr(self, key, value)

    @classmethod
    def process(inferred, record):
        """Process results and return a loaded instance.

        :param object inferred: Instance of the class itself
        :param dict record: Record to use for loading
        :return: Instance of the loaded class
        """
        return inferred(record)


class SslHistoryResponse(Response):

    """Result object to ease interaction with data."""

    def __init__(self, *args, **kwargs):
        """Inherit from the base class."""
        super(SslHistoryResponse, self).__init__(*args, **kwargs)

        self._records = list()
        self._process_records()

    def _process_records(self):
        """Process the SSL certificate history data."""
        self._records = list()
        for record in self._results.get('results', []):
            wrapped = HistoryRecord.process(record)
            self._records.append(wrapped)

    def get_records(self):
        return self._records

    @property
    def records(self):
        return self._records

    @property
    def csv(self):
        """Output data as CSV.

        :return: String of formatted data
        """
        output = ''
        fields = ['SHA-1', 'First Seen', 'Last Seen']
        output += ','.join(fields) + "\n"
        for record in self._records:
            output += "%s,%s,%s" % (
                record.sha1,
                record.firstSeen,
                record.lastSeen
            ) + "\n"
        output = output.strip()

        return output

    @property
    def table(self):
        """Output data as table.

        :return: Table of formatted data
        """
        output = ''
        headers = ['SHA-1', 'First Seen', 'Last Seen']
        records = list()
        for record in self._records:
            records.append([record.sha1, record.firstSeen, record.lastSeen])
        output = tabulate(records, headers)

        return output

    @property
    def text(self):
        """Output data as text.

        :return: String of formatted data
        """
        output = ''
        for item in self._records:
            output += "[*] SHA-1: %s\n" % item.sha1
            output += "=> First Seen: %s\n" % item.firstSeen
            output += "=> Last Seen: %s\n" % item.lastSeen
        output = output.strip()

        return output
