from datetime import datetime
import pprint
from passivetotal.analyzer._common import (
    RecordList, Record, FirstLastSeen, PagedRecordList
)
from passivetotal.analyzer import get_api, get_config, get_object



class TrackerHistory(RecordList, PagedRecordList):

    """Historical web component data."""

    def _get_shallow_copy_fields(self):
        return ['_totalrecords']
    
    def _get_sortable_fields(self):
        return ['firstseen','lastseen','category','label','hostname']
    
    def _get_dict_fields(self):
        return ['totalrecords']
    
    @property
    def as_dict(self):
        d = super().as_dict
        d.update({
            'distinct_hostnames': [ str(host) for host in self.hostnames ],
            'distinct_categories': self.categories,
            'distinct_values': self.values
        })
        return d
    
    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalRecords')
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(TrackerRecord(result))

    @property
    def hostnames(self):
        """List of unique hostnames in the tracker record list."""
        return set(
            get_object(host) for host in set([record.hostname for record in self])
        )
    
    @property
    def categories(self):
        """List of unique categories (types) in the tracker record list."""
        return set([record.category for record in self])
    
    @property
    def values(self):
        """List of unique tracker values in the tracker record list."""
        return set([record.value for record in self])



class TrackerRecord(Record, FirstLastSeen):

    """Record of an observed trackers."""

    def __init__(self, api_response):
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._value = api_response.get('attributeValue')
        self._trackertype = api_response.get('attributeType')
        self._hostname = api_response.get('hostname')
    
    def __str__(self):
        return '[{0.trackertype}] "{0.value}" ({0.firstseen_date} to {0.lastseen_date})'.format(self)
    
    def __repr__(self):
        return '<ComponentRecord "{0.value}">'.format(self)
    
    def _get_dict_fields(self):
        return ['str:firstseen','str:lastseen','value','trackertype','hostname']
    
    @property
    def value(self):
        """Value of the tracker."""
        return self._value

    @property
    def hostname(self):
        """Hostname the tracker was observed on."""
        return self._hostname
    
    @property
    def trackertype(self):
        """Type or category of web tracker; alias of `TrackerRecord.trackertype`."""
        return self._trackertype
    
    @property
    def category(self):
        """Category or type of web tracker."""
        return self._trackertype



class HasTrackers:

    """An object with web tracker history."""

    def _api_get_trackers(self, start_date=None, end_date=None):
        """Query the host attributes API for web tracker history.
        
        Only the first page of results is returned; pagination is not
        supported. Check the totalrecords attribute of the response object
        to determine if more records are available.
        """
        response = get_api('HostAttributes').get_trackers(
            query=self.get_host_identifier(),
            start=start_date,
            end=end_date
        )
        self._trackers = TrackerHistory(response)
        return self._trackers
    
    @property
    def trackers(self):
        """History of trackers observed on this host.

        Trackers are analytics codes, social network accounts, and other unique
        details extracted from the web page by RiskIQ crawlers based on detection
        logic programmed by RiskIQ analysts.

        :rtype: :class:`passivetotal.analyzer.trackers.TrackersHistory`
        """
        if getattr(self, '_trackers', None) is not None:
            return self._trackers
        config = get_config()
        return self._api_get_trackers(
            start_date=config['start_date'],
            end_date=config['end_date']
        )