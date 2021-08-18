from passivetotal.analyzer._common import (
    RecordList, Record, FirstLastSeen, PagedRecordList, ForPandas, AnalyzerError, AnalyzerAPIError,
    FilterDomains
)
from passivetotal.analyzer import get_api, get_config, get_object



class TrackerHistory(RecordList, PagedRecordList, ForPandas):

    """Historical web component data."""

    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_query']
    
    def _get_sortable_fields(self):
        return ['firstseen','lastseen','category','label','hostname']
    
    def _get_dict_fields(self):
        return ['totalrecords']
    
    @property
    def as_dict(self):
        d = super().as_dict
        d.update({
            'distinct_hostnames': [ str(host) for host in self.hostnames ],
            'distinct_categories': list(self.categories),
            'distinct_values': list(self.values)
        })
        return d
    
    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalRecords', 0)
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(TrackerRecord(result, self._query))

    @property
    def hostnames(self):
        """List of unique hostnames in the tracker record list."""
        return set(
            get_object(host) for host in set([record.hostname for record in self if record.hostname is not None])
        )
    
    @property
    def categories(self):
        """List of unique categories (types) in the tracker record list."""
        return set([record.category for record in self if record.category is not None])
    
    @property
    def values(self):
        """List of unique tracker values in the tracker record list."""
        return set([record.value for record in self if record.value is not None])



class TrackerRecord(Record, FirstLastSeen, ForPandas):

    """Record of an observed trackers."""

    def __init__(self, api_response, query=None):
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._value = api_response.get('attributeValue')
        self._trackertype = api_response.get('attributeType')
        self._hostname = api_response.get('hostname')
        self._query = query
    
    def __str__(self):
        return '[{0.trackertype}] "{0.value}" ({0.firstseen_date} to {0.lastseen_date})'.format(self)
    
    def __repr__(self):
        return '<TrackerRecord "{0.value}">'.format(self)
    
    def _get_dict_fields(self):
        return ['str:firstseen','str:lastseen','value','trackertype','hostname']
    
    def to_dataframe(self):
        """Render this object as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['query','firstseen','lastseen','trackertype','value','hostname']
        as_d = {
            'query': self._query,
            'firstseen': self.firstseen,
            'lastseen': self.lastseen,
            'trackertype': self.trackertype,
            'value': self.value,
            'hostname': self.hostname,
        }
        return pd.DataFrame([as_d], columns=cols)

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
        """Type or category of web tracker."""
        return self._trackertype
    
    @property
    def category(self):
        """Category or type of web tracker; alias of `TrackerRecord.trackertype`."""
        return self._trackertype
    
    @property
    def tracker(self):
        """Tracker as a `Tracker` object to aid pivoting to other related IPs or hosts.
        
        :rtype: :class:`passivetotal.analyzer.trackers.Tracker`
        """
        return Tracker(self.trackertype, self.value)



class TrackerSearchResults(RecordList, ForPandas, FilterDomains):

    """Search results from a tracker query."""

    def __init__(self, api_response=None, query=None, tracker_type=None, search_type=None):
        self._query = query
        self._records = []
        self._totalrecords = 0
        if api_response is not None:
            self.parse(api_response, tracker_type, search_type)

    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_query']
    
    def _get_sortable_fields(self):
        return ['firstseen','lastseen','searchtype','trackertype','query','host']
    
    def _get_dict_fields(self):
        return ['totalrecords']
    
    @property
    def as_dict(self):
        d = super().as_dict
        return d
    
    def parse(self, api_response, tracker_type, search_type):
        """Parse an API response."""
        self._totalrecords = self._totalrecords + api_response.get('totalRecords', 0)
        for result in api_response.get('results', []):
            self._records.append(TrackerSearchRecord(result, self._query, tracker_type, search_type))
    
    @property
    def query(self):
        """Query used to return this set of search results."""
        return self._query
    
    @property
    def totalrecords(self):
        """Total number of available records; may be greater than the number of results returned by the API."""
        return self._totalrecords



class TrackerSearchRecord(Record, FirstLastSeen, ForPandas):

    """Record representing a single search result in a tracker search."""

    def __init__(self, api_response, query=None, tracker_type=None, search_type=None):
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._query = query
        self._trackertype = tracker_type
        self._searchtype = search_type
        self._entity = api_response.get('entity',None)
    
    def __str__(self):
        return '[{0.trackertype}] @ "{0.entity}" ({0.firstseen_date} to {0.lastseen_date})'.format(self)
    
    def __repr__(self):
        return '<TrackerSearchRecord "{0.query} > {0.entity}">'.format(self)
    
    def _get_dict_fields(self):
        return ['str:firstseen','str:lastseen','query','str:host','trackertype','searchtype']
    
    def to_dataframe(self):
        """Render this object as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['query','host','trackertype','firstseen','lastseen','searchtype']
        as_d = {
            'query': self._query,
            'host': self.host,
            'trackertype': self.trackertype,
            'firstseen': self.firstseen,
            'lastseen': self.lastseen,
            'searchtype': self.searchtype
        }
        return pd.DataFrame([as_d], columns=cols)

    @property
    def entity(self):
        """Entity where a tracker was found - typically a hostname or an IP address.
        
        Returns the actual value returned by the API in the 'entity' response field.
        """
        return self._entity
    
    @property
    def host(self):
        """Host where a tracker was found.
        
        Returns either an `analyzer.Hostname` or `analyzer.IPAddress` object depending on
        the type of search which produced this record.
        """
        if self._searchtype == 'addresses':
            return get_object(self.entity, type='IPAddress')
        elif self._searchtype == 'hosts' or self._searchtype is None:
            return get_object(self.entity, type='Hostname')
        else:
            return None
    
    @property
    def query(self):
        """Query that produced this search result."""
        return self._query
    
    @property
    def searchtype(self):
        """Type of search (hostnames or IP addresses) that produced this search result.
        
        This value defines the type of records returned - either hostnames or IPs."""
        return self._searchtype
    
    @property
    def trackertype(self):
        """Type of tracker found on the entity (host) referenced in this search result."""
        return self._trackertype

    @property
    def tracker(self):
        """Tracker as a `Tracker` object to aid pivoting to other related IPs or hosts.
        
        :rtype: :class:`passivetotal.analyzer.trackers.Tracker`
        """
        return Tracker(self.trackertype, self.value)



class Tracker:

    """A web tracker with a type and value.
    
    In addition to a simple type/value mapping, this class also provides
    `ips` and `hostname` properties to find other entities that
    have the same type/value tuple.
    """

    _instances = {}

    def __new__(cls, trackertype, value):
        valuehash = hash((trackertype, value))
        self = cls._instances.get(valuehash)
        if not self:
            self = cls._instances[valuehash] = object.__new__(cls)
            self._type = trackertype
            self._value = value
            self._ips = None
            self._hostnames = None
        return self
    
    def __str__(self):
        return '{0.trackertype}:{0.value}'.format(self)
    
    def __repr__(self):
        return '<Tracker {}>'.format(str(self))
    
    def _api_search(self, searchtype):
        attrs = {
            'hosts': '_hostnames',
            'addresses': '_ips'
        }
        try:
            response = (get_api('HostAttributes')
                .search_trackers_by_type(query=self._value, type=self._type, searchType=searchtype)
            )
        except Exception:
            raise AnalyzerError
        setattr(self, attrs[searchtype], TrackerSearchResults(response, self._value, self._type, searchtype))
    
    @property
    def trackertype(self):
        """Type of tracker as defined by RiskIQ analysts."""
        return self._type
    
    @property
    def value(self):
        """Tracker value as observed."""
        return self._value
    
    @property
    def observations_by_ip(self):
        """IP addresses of hosts where this tracker was observed.
        
        :rtype: :class:`passivetotal.analyzer.trackers.TrackerSearchResults`
        """
        if self._ips is None:
            self._api_search('addresses')
        return self._ips
    
    @property
    def observations_by_hostname(self):
        """Hostnames of sites where this tracker was observed.
        
        :rtype: :class:`passivetotal.analyzer.trackers.TrackerSearchResults`
        """
        if self._hostnames is None:
            self._api_search('hosts')
        return self._hostnames



class HasTrackers:

    """An object with web tracker history."""

    _REFERENCE_TRACKER_TYPES = {
        'Hostname': ['DocumentBaseHost','HTTrackSourceHost','MarkOfTheWebSourceHost','SingleFileSourceHost'],
        'IPAddress': ['DocumentBaseAddress','HTTrackSourceAddress','MarkOfTheWebSourceAddress','SingleFileSourceAddress']
    }

    def _api_get_trackers(self, start_date=None, end_date=None):
        """Query the host attributes API for web tracker history.
        
        Only the first page of results is returned; pagination is not
        supported. Check the totalrecords attribute of the response object
        to determine if more records are available.
        """
        query=self.get_host_identifier()
        response = get_api('HostAttributes').get_trackers(
            query=query,
            start=start_date,
            end=end_date
        )
        self._trackers = TrackerHistory(response, query)
        return self._trackers
    
    def _api_get_tracker_references(self):
        """Query the host attributes API and search trackers for multiple trackertypes and searchtypes."""
        self._tracker_references = TrackerSearchResults(query=self.get_host_identifier())
        tracker_types = self._REFERENCE_TRACKER_TYPES.get('Hostname' if self.is_hostname else 'IPAddress')
        for trackertype in tracker_types:
            for searchtype in ['addresses','hosts']:
                try:
                    result = get_api('HostAttributes').search_trackers_by_type(
                        query=self.get_host_identifier(),
                        type=trackertype,
                        searchType=searchtype
                    )
                    self._tracker_references.parse(result, trackertype, searchtype)
                except AnalyzerAPIError as e:
                    if e.status_code == 404:
                        continue
                    raise e
        return self._tracker_references

    @property
    def trackers(self):
        """History of trackers observed on this host.

        Trackers are analytics codes, social network accounts, and other unique
        details extracted from the web page by RiskIQ crawlers based on detection
        logic programmed by RiskIQ analysts.

        :rtype: :class:`passivetotal.analyzer.trackers.TrackerHistory`
        """
        if getattr(self, '_trackers', None) is not None:
            return self._trackers
        config = get_config()
        return self._api_get_trackers(
            start_date=config['start_date'],
            end_date=config['end_date']
        )
    
    @property
    def tracker_references(self):
        """Hosts with trackers that have this host as the value.
        
        Performs several API queries to create a composite result; create an instance of
        :class:`passivetotal.analyzer.Tracker` if you need more granular control.

        :rtype: :class:`passivetotal.analyzer.trackers.TrackerSearchResults`
        """
        if getattr(self, '_tracker_references', None) is not None:
            return self._tracker_references
        return self._api_get_tracker_references()