from datetime import datetime
import pprint
from passivetotal.analyzer._common import (
    RecordList, Record, FirstLastSeen, PagedRecordList, ForPandas, FilterDomains
)
from passivetotal.analyzer import get_api, get_config, get_object



class HostpairHistory(RecordList, PagedRecordList, ForPandas, FilterDomains):

    """Historical connections between hosts."""

    def __init__(self, api_response=None, direction=None, query=None):
        self._direction = direction
        self._query = query
        if api_response:
            self.parse(api_response)

    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_direction','_query']
    
    def _get_sortable_fields(self):
        return ['firstseen','lastseen','cause','child','parent']

    def _get_dict_fields(self):
        return ['totalrecords','direction']
    
    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalRecords', 0)
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(HostpairRecord(result, direction=self._direction, query=self._query))
    
    @property
    def as_dict(self):
        d = super().as_dict
        d.update({
            'distinct_causes': list(self.causes),
            'distinct_hosts': [ str(h) for h in self.hosts ],
        })
        return d
    
    @property
    def direction(self):
        """Direction of the paired relationship - children or parents."""
        return self._direction
    
    @property
    def causes(self):
        """Set of unique causes in the hostpair record list."""
        return set([record.cause for record in self if record.cause is not None])

    @property
    def children(self):
        """Set of unique child hostnames in the hostpairs record list."""
        return set([record.child for record in self if record.child is not None])
    
    @property
    def parents(self):
        """Set of unique parent hostnames in the hostpairs record list."""
        return set([record.parent for record in self if record.parent is not None])
    
    @property
    def hosts(self):
        """List of unique paired hosts (IPs or hostnames).

        Returns `Hostpairs.children` or `Hostpairs.parents` depending on
        the value of `Hostpairs.direction`
        """
        return getattr(self, self._direction)
    
    @property
    def domains(self):
        """List of unique registered domains."""
        def get_domain(host):
            try:
                return host.registered_domain
            except AttributeError:
                pass
        return set([])
    



class HostpairRecord(Record, FirstLastSeen, ForPandas):

    """Record of observed trackers."""

    def __init__(self, api_response, direction=None, query=None):
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._child = api_response.get('child')
        self._parent = api_response.get('parent')
        self._cause = api_response.get('cause')
        self._direction = direction
        self._query = query
    
    def __str__(self):
        return '{0.parent} > {0.child} [{0.cause}] ({0.firstseen_date} to {0.lastseen_date})'.format(self)
    
    def __repr__(self):
        return '<HostpairRecord [{0.cause}]>'.format(self)
    
    def _get_dict_fields(self):
        return ['str:firstseen','str:lastseen','str:child','str:parent','cause']
    
    def to_dataframe(self):
        """Render this object as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['query','direction','firstseen','lastseen','child','parent','cause']
        as_d = {
            'query': self._query,
            'direction': self._direction,
            'firstseen': self.firstseen,
            'lastseen': self.lastseen,
            'child': self._child,
            'parent': self._parent,
            'cause': self._cause
        }
        return pd.DataFrame([as_d], columns=cols)
    
    @property
    def cause(self):
        """Cause or category of the pairing, if known."""
        return self._cause

    @property
    def child(self):
        """Descendant hostname for this pairing.
        
        :retval: :class:`passivetotal.analyzer.hostname.Hostname`
        """
        return get_object(self._child)
    
    @property
    def direction(self):
        """Direction of the relationship - parent or child."""
        return 'parent' if self._direction=='parents' else 'child'

    @property
    def parent(self):
        """Parent hostname for this pairing.
        
        :retval: :class:`passivetotal.analyzer.hostname.Hostname`
        """
        return get_object(self._parent)
        
    @property
    def host(self):
        """Returns the parent or the child host depending on whether the direction is
        "parent" or "child". 

        :retval: :class:`passivetotal.analyzer.hostname.Hostname`
        """
        return getattr(self, self.direction)



class HasHostpairs:

    """An object with hostpair history."""

    def _reset_hostpairs(self):
        """Reset the instance hostpairs private attributes."""
        self._pairs = {}
        self._pairs['parents'] = None
        self._pairs['children'] = None

    def _api_get_hostpairs(self, direction, start_date=None, end_date=None):
        """Query the hostpairs API for the parent or child relationships.
        
        Only the first page of results is returned; pagination is not
        supported. Check the totalrecords attribute of the response object
        to determine if more records are available.
        """
        query=self.get_host_identifier()
        response = get_api('HostAttributes').get_host_pairs(
            query=query,
            direction=direction,
            start=start_date,
            end=end_date
        )
        self._pairs[direction] = HostpairHistory(response, direction, query)
        return self._pairs[direction]

    @property
    def hostpair_parents(self):
        """Hostpair relationships where this host is the child.

        :rtype: :class:`passivetotal.analyzer.hostpairs.HostpairHistory`
        """
        if self._pairs['parents'] is not None:
            return self._pairs['parents']
        config = get_config()
        return self._api_get_hostpairs(
            direction='parents',
            start_date=config['start_date'],
            end_date=config['end_date']
        )
    
    @property
    def hostpair_children(self):
        """Hostpair relationships where this host is the parent.

        :rtype: :class:`passivetotal.analyzer.hostpairs.HostpairHistory`
        """
        if self._pairs['children'] is not None:
            return self._pairs['children']
        config = get_config()
        return self._api_get_hostpairs(
            direction='children',
            start_date=config['start_date'],
            end_date=config['end_date']
        )
