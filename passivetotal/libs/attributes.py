#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

import collections
from future.utils import iteritems
from tabulate import tabulate
from passivetotal.api import Client
from passivetotal.response import Response
# const
from passivetotal.common.exceptions import INVALID_VALUE_TYPE


class AttributeRequest(Client):

    """Client to interface with the account calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(AttributeRequest, self).__init__(*args, **kwargs)

    def get_host_attribute_trackers(self, **kwargs):
        """Get trackers associated with a particular host or IP address.

        Reference: https://api.passivetotal.org/api/docs/#api-Host_Attributes-GetTrackers

        :return: Dict of results with tracking IDs
        """
        return self._get('host-attributes', 'trackers', **kwargs)

    def get_host_attribute_components(self, **kwargs):
        """Get componets associated with a particular host or IP address.

        Reference: https://api.passivetotal.org/api/docs/#api-Host_Attributes-GetComponents

        :return: Dict of resuts with component information
        """
        return self._get('host-attributes', 'components', **kwargs)

    def search_trackers(self, **kwargs):
        """Search tracking IDs for associated hosts.

        Reference: https://api.passivetotal.org/api/docs/#api-Host_Attributes-SearchTrackers

        :return: Dict of matching hosts using a tracking ID
        """
        return self._get('trackers', 'search', **kwargs)


class GeneticAttributeRecord(object):
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

    def get_record(self):
        """Get the raw record."""
        return self._record


class AttributeResponse(Response):

    """Result object to ease interaction with data."""

    def __init__(self, *args, **kwargs):
        """Inherit from the base class."""
        super(AttributeResponse, self).__init__(*args, **kwargs)
        self._process_records()

    def _process_records(self):
        """Process the passive DNS data."""
        self._records = list()
        for record in self.results:
            wrapped = GeneticAttributeRecord.process(record)
            self._records.append(wrapped)

    def get_records(self):
        """Get the loaded records."""
        return self._records

    @property
    def csv(self):
        """Output data as CSV.

        :return: String of formatted data
        """
        if len(self.results) == 0:
            return "No results were found"
        output = ''
        first_item = self.results[0]
        ordered = collections.OrderedDict(sorted(first_item.items()))
        fields = ordered.keys()
        output += ', '.join(fields) + "\n"
        for record in self.results:
            ordered = collections.OrderedDict(sorted(record.items()))
            ordered = ordered.values()
            output += ', '.join(ordered) + "\n"
        output = output.strip()

        return output

    @property
    def table(self):
        """Output data as table.

        :return: Table of formatted data
        """
        if len(self.results) == 0:
            return "No results were found"
        first_item = self.results[0]
        ordered = collections.OrderedDict(sorted(first_item.items()))
        headers = ordered.keys()
        records = []
        for record in self.results:
            ordered = collections.OrderedDict(sorted(record.items()))
            ordered = ordered.values()
            records.append(ordered)
        output = tabulate(records, headers)

        return output

