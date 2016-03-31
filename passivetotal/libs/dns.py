#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

import collections
import datetime
from future.utils import iteritems
from tabulate import tabulate
import sys
# custom
from passivetotal.api import Client
from passivetotal.response import Response
from passivetotal.common.utilities import is_ip
# exceptions
from passivetotal.common.exceptions import INVALID_VALUE_TYPE

python2 = (sys.version_info[0] == 2)
python3 = (sys.version_info[0] == 3)
if python2:
    from stix.core import STIXHeader
    from stix.core import STIXPackage
    from stix.indicator import Indicator
    from cybox.objects.address_object import Address
    from cybox.objects.domain_name_object import DomainName


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


class DnsRecord(object):

    """Provide some basic helpers for the DNS records."""

    def __init__(self, record):
        """Initialize the class.

        :param dict record: Record to load into the class
        """
        if type(record) != dict:
            raise INVALID_VALUE_TYPE("Record must be of type dict")
        self._record = record
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

    def _load_time(self, time_period):
        """Convert a str date to true datetime.

        :param str time_period: Date period of the record
        :return: Loaded datetime object from the string
        """
        return datetime.datetime.strptime(
            time_period, "%Y-%m-%d %H:%M:%S"
        )

    def get_observed_days(self):
        """Get the amount of days observed for the record period.

        :return: Number of days observed
        """
        first_seen = self._load_time(self.firstSeen)
        last_seen = self._load_time(self.lastSeen)
        return (last_seen - first_seen).days

    def get_days_until_now(self):
        """Get the amount of days from last seen until today.

        :return: Nunber of days until now
        """
        last_seen = self._load_time(self.lastSeen)
        current_time = datetime.datetime.now()
        return (current_time - last_seen).days

    def get_source_count(self):
        """Get the number of sources used to create the record.

        :return: Number of sources used for the record
        """
        return len(self.sources)


class DnsResponse(Response):

    """Result object to ease interaction with data."""

    def __init__(self, *args, **kwargs):
        """Inherit from the base class."""
        super(DnsResponse, self).__init__(*args, **kwargs)
        self._process_records()

    def _process_records(self):
        """Process the passive DNS data."""
        self._records = list()
        for record in self.results:
            wrapped = DnsRecord.process(record)
            self._records.append(wrapped)

    def get_records(self):
        """Get the DNS records."""
        return self._records

    def get_observed_days(self):
        """Get the amount of days observed for the query period.

        :return: Nunber of observed days
        """
        first_seen = self._load_time(self.firstSeen, "%Y-%m-%d %H:%M:%S")
        last_seen = self._load_time(self.lastSeen, "%Y-%m-%d %H:%M:%S")
        return (last_seen - first_seen).days

    def get_days_until_now(self):
        """Get the amount of days from last seen until today.

        :return: Nunber of days until now
        """
        last_seen = self._load_time(self.lastSeen, "%Y-%m-%d %H:%M:%S")
        current_time = datetime.datetime.now()
        return (current_time - last_seen).days

    def get_source_variety(self):
        """Get the contribution count for each source for the results.

        :return: Dict of sources and their counts based on data
        """
        sources = dict()
        for item in self._records:
            for source in item.source:
                if source in sources:
                    sources[source] += 1
                else:
                    sources[source] = 1

        return sources

    @property
    def csv(self):
        """Output data as CSV.

        :return: String of formatted data
        """
        if len(self.results) == 0:
            return "No results were found"
        output = ''
        first_item = self.results[0]
        if 'collected' in first_item:
            del first_item['collected']
        ordered = collections.OrderedDict(sorted(first_item.items()))
        fields = ordered.keys()
        output += ', '.join(fields) + "\n"
        for record in self.results:
            if 'collected' in record:
                del record['collected']
            ordered = collections.OrderedDict(sorted(record.items()))
            ordered = ordered.values()
            ordered[4] = '|'.join(ordered[4])
            output += ', '.join(ordered) + "\n"
        output = output.strip()

        return output

    @property
    def text(self):
        """Output data as text.

        :return: String of formatted data
        """
        output = ''
        output += "[*] Query: %s\n" % self.queryValue
        output += "[*] First Seen: %s\n" % self.firstSeen
        output += "[*] Last Seen: %s\n" % self.lastSeen
        output += "[*] Total Records: %d\n" % len(self.results)
        output += "[*] Records:\n"
        output += "=> First Seen\t\tLast Seen\t\tResolution\tSources\n"
        for record in self._records:
            output += "=> %s\t%s\t%s\t%s\n" % (
                record.firstSeen,
                record.lastSeen,
                record.resolve,
                ', '.join(record.source)
            )

        return output

    @property
    def table(self):
        """Output data as table.

        :return: Table of formatted data
        """
        if len(self.results) == 0:
            return "No results were found"
        first_item = self.results[0]
        if 'collected' in first_item:
            del first_item['collected']
        ordered = collections.OrderedDict(sorted(first_item.items()))
        headers = ordered.keys()
        records = []
        for record in self.results:
            if 'collected' in record:
                del record['collected']
            if 'recordHash' in record:
                del record['recordHash']
            ordered = collections.OrderedDict(sorted(record.items()))
            ordered = ordered.values()
            ordered[4] = '|'.join(ordered[4])
            records.append(ordered)
        output = tabulate(records, headers)

        return output

    @property
    def stix(self):
        """Output data as STIX.

        STIX is highly subjective and difficult to format without getting more
        data from the user. Passive DNS results are formtted into a STIX
        watchlist with descriptions and other details about the record.

        :return: STIX formatted watchlist
        """
        if python3:
            raise RuntimeError("STIX is not supported when using Python 3 due to dependency libraries.")

        stix_package = STIXPackage()
        stix_header = STIXHeader()
        stix_header.description = "Passive DNS resolutions associated" \
                                  " with %s during the time periods of " \
                                  " %s - %s" % (self.queryValue,
                                                self.firstSeen,
                                                self.lastSeen)
        stix_package.stix_header = stix_header
        for record in self._records:
            indicator = Indicator(
                title="Observed from %s - %s" % (
                    record.firstSeen,
                    record.lastSeen
                ),
                short_description="Resolution observed by %s." % (
                    ','.join(record.source)
                ),
                description="Passive DNS data collected and aggregated from" \
                            " PassiveTotal services."
            )

            if is_ip(record.resolve):
                indicator.add_indicator_type('IP Watchlist')
                ioc = Address(
                    address_value=record.resolve,
                    category=Address.CAT_IPV4
                )
            else:
                indicator.add_indicator_type('Domain Watchlist')
                ioc = DomainName(value=record.resolve)

            ioc.condition = "Equals"
            indicator.add_observable(ioc)
            stix_package.add_indicator(indicator)
        output = stix_package.to_xml()

        return output


class UniqueDnsRecord(object):

    """Provide some basic helpers for the DNS unique records."""

    def __init__(self, record):
        """Initialize the class.

        :param list results: Record to load into the class
        """
        if type(record) != list:
            raise INVALID_VALUE_TYPE("Record must be of type list")
        self._record = record
        self.resolve, self.count = record

    @classmethod
    def process(inferred, record):
        """Process results and return a loaded instance.

        :param object inferred: Instance of the class itself
        :param dict record: Record to use for loading
        :return: Instance of the loaded class
        """
        return inferred(record)


class DnsUniqueResponse(Response):

    """Result object to ease interaction with data."""

    def __init__(self, *args, **kwargs):
        """Inherit from the base class."""
        super(DnsUniqueResponse, self).__init__(*args, **kwargs)

        self._records = list()
        self._process_records()

    def _process_records(self):
        """Process the passive DNS data."""
        self._records = list()
        for record in self.frequncy:
            wrapped = UniqueDnsRecord.process(record)
            self._records.append(wrapped)

    def get_records(self):
        """Get a list of unique resolution records."""
        return self._records

    @property
    def csv(self):
        """Output data as CSV.

        :return: String of formatted data
        """
        output = ''
        fields = ['Resolution', 'Frequency']
        output += ', '.join(fields) + "\n"
        for record in self._records:
            output += "%s, %d" % (record.resolve, record.count) + "\n"
        output = output.strip()

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
        output += "[*] Query: %s\n" % self.queryValue
        output += "[*] Total Records: %d\n" % len(self.results)
        output += "[*] Records:\n"
        output += "=> Resolution\t\tFrequency\n"
        for record in self._records:
            output += "=> %s\t\t%d\n" % (
                record.resolve,
                record.count
            )

        return output

    @property
    def table(self):
        """Output data as table.

        :return: Table of formatted data
        """
        output = ''
        headers = ['Resolution', 'Frequency']
        records = list()
        for record in self._records:
            records.append([record.resolve, record.count])
        output = tabulate(records, headers)

        return output

    @property
    def stix(self):
        """Output data as STIX.

        STIX is highly subjective and difficult to format without getting more
        data from the user. Passive DNS results are formtted into a STIX
        watchlist with descriptions and other details about the record.

        :return: STIX formatted watchlist
        """
        if python3:
            raise RuntimeError("STIX is not supported when using Python 3 due to dependency libraries.")

        stix_package = STIXPackage()
        stix_header = STIXHeader()
        stix_header.description = "Passive DNS resolutions associated" \
                                  " with %s." % (self.query_value)
        stix_package.stix_header = stix_header
        for record in self._records:
            indicator = Indicator(
                title="Showed up %d times in passive DNS" % (record.count),
                description="Passive DNS data collected and aggregated from"
                            " PassiveTotal services."
            )

            if is_ip(record.resolve):
                indicator.add_indicator_type('IP Watchlist')
                ioc = Address(
                    address_value=record.resolve,
                    category=Address.CAT_IPV4
                )
            else:
                indicator.add_indicator_type('Domain Watchlist')
                ioc = DomainName(value=record.resolve)

            ioc.condition = "Equals"
            indicator.add_observable(ioc)
            stix_package.add_indicator(indicator)
        output = stix_package.to_xml()

        return output
