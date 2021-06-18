from datetime import datetime
import pprint
from passivetotal.analyzer._common import (
    RecordList, Record, FirstLastSeen, PagedRecordList, ForPandas
)
from passivetotal.analyzer import get_api, get_config



class ComponentHistory(RecordList, PagedRecordList, ForPandas):

    """Historical web component data.
    
    Web components represent technology that powers Internet-facing services.
    Component categories are derived from detection logic explicitly created by 
    RiskIQ analysts. Component values and, when available, component versions,
    describe the web technology discovered on a given web host.
    """

    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_query']
    
    def _get_sortable_fields(self):
        return ['firstseen','lastseen','category','label','hostname']
    
    def _get_dict_fields(self):
        return ['totalrecords']
    
    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalRecords', 0)
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(ComponentRecord(result, query=self._query))
    
    @property
    def as_dict(self):
        d = super().as_dict
        d.update({
            'distinct_hostnames': [ str(h) for h in self.hostnames ],
            'distinct_categories': [ cat for cat in self.categories ],
            'distinct_values': [ val for val in self.values ],
        })
        return d

    @property
    def hostnames(self):
        """List of unique hostnames in the component record list."""
        from passivetotal.analyzer import Hostname
        return set(
            Hostname(host) for host in set([record.hostname for record in self if record.hostname is not None])
        )
    
    @property
    def categories(self):
        """List of unique categories in the component record list."""
        return set([record.category for record in self if record.category is not None])
    
    @property
    def values(self):
        """List of unique values (labels) in the component record list."""
        return set([record.label for record in self if record.label is not None])



class ComponentRecord(Record, FirstLastSeen, ForPandas):

    """Record of an observed web component."""

    def __init__(self, api_response, query=None):
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._version = api_response.get('version')
        self._category = api_response.get('category')
        self._label = api_response.get('label')
        self._hostname = api_response.get('hostname')
        self._query = query
    
    def __str__(self):
        version = 'v{} '.format(self.version) if self.version else ''
        return '[{0.category}] {0.label} {1}({0.firstseen_date} to {0.lastseen_date})'.format(self, version)
    
    def __repr__(self):
        return '<ComponentRecord "{0.label}">'.format(self)

    def _get_dict_fields(self):
        return ['query','category','str:firstseen','str:lastseen','label','version','str:hostname']
    
    def to_dataframe(self):
        """Render this object as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['query','firstseen','lastseen','category','label','version']
        as_d = {
            f: getattr(self, f) for f in cols
        }
        as_d['hostname'] = self._hostname
        cols.append('hostname')
        return pd.DataFrame([as_d], columns=cols)
    
    @property
    def category(self):
        """Category or type of the web component."""
        return self._category

    @property
    def hostname(self):
        """Hostname where the component was identified."""
        return self._hostname
    
    @property
    def label(self):
        """Value of the web component; alias of `ComponentRecord.value`."""
        return self._label
    
    @property
    def query(self):
        """API query value (hostname or IP address)."""
        return self._query

    @property
    def value(self):
        """Value of the web component."""
        return self._label

    @property
    def version(self):
        """Version of the web component, if available."""
        return self._version



class HasComponents:

    """An object with web component history."""

    def _api_get_components(self, start_date=None, end_date=None):
        """Query the host attributes API for web component history. 

        Only the first page of results is returned; pagination is not
        supported. Check the totalrecords attribute of the response object
        to determine if more records are available.
        """
        query = self.get_host_identifier()
        response = get_api('HostAttributes').get_components(
            query=query,
            start=start_date,
            end=end_date
        )
        self._components = ComponentHistory(response, query=query)
        return self._components
        
    @property
    def components(self):
        """History of web components observed on this host.
        
        Web components represent technology that powers Internet-facing services.
        Component categories are derived from detection logic explicitly created by 
        RiskIQ analysts. Component values and, when available, component versions,
        describe the web technology discovered on a given web host.

        :rtype: :class:`passivetotal.analyzer.components.ComponentHistory`
        """
        if getattr(self, '_components', None) is not None:
            return self._components
        config = get_config()
        return self._api_get_components(
            start_date=config['start_date'],
            end_date=config['end_date']
        )