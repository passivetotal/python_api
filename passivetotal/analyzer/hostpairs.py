from datetime import datetime
import pprint
from passivetotal.analyzer._common import (
    RecordList, Record, FirstLastSeen, PagedRecordList
)
from passivetotal.analyzer import get_api, get_config, get_object



class HostpairHistory(RecordList, PagedRecordList):

    """Historical connections between hosts."""

    def __init__(self, api_response=None, direction=None):
        self._direction = direction
        if api_response:
            self.parse(api_response)

    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_direction']
    
    def _get_sortable_fields(self):
        return ['firstseen','lastseen','cause','child','parent']

    def _get_dict_fields(self):
        return ['totalrecords','direction']
    
    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalRecords')
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(HostpairRecord(result))
    
    @property
    def as_dict(self):
        d = super().as_dict
        d.update({
            'distinct_causes': self.causes,
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
        return set([record.cause for record in self])

    @property
    def children(self):
        """Set of unique child hostnames in the hostpairs record list."""
        from passivetotal.analyzer import Hostname
        return set([record.child for record in self])
    
    @property
    def parents(self):
        """Set of unique parent hostnames in the hostpairs record list."""
        from passivetotal.analyzer import Hostname
        return set([record.parent for record in self])
    
    @property
    def hosts(self):
        """List of unique paired hosts (IPs or hostnames).

        Returns `Hostpairs.children` or `Hostpairs.parents` depending on
        the value of `Hostpairs.direction`
        """
        return getattr(self, self._direction)



class HostpairRecord(Record, FirstLastSeen):

    """Record of observed trackers."""

    def __init__(self, api_response):
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._child = api_response.get('child')
        self._parent = api_response.get('parent')
        self._cause = api_response.get('cause')
    
    def __str__(self):
        return '{0.parent} > {0.child} [{0.cause}] ({0.firstseen_date} to {0.lastseen_date})'.format(self)
    
    def __repr__(self):
        return '<HostpairRecord [{0.cause}]>'.format(self)
    
    def _get_dict_fields(self):
        return ['str:firstseen','str:lastseen','str:child','str:parent','cause']
    
    @property
    def cause(self):
        """Cause or category of the pairing, if known."""
        return self._cause

    @property
    def child(self):
        """Descendant hostname for this pairing."""
        return get_object(self._child)
    
    @property
    def parent(self):
        """Parent hostname for this pairing."""
        return get_object(self._parent)



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
        response = get_api('HostAttributes').get_host_pairs(
            query=self.get_host_identifier(),
            direction=direction,
            start=start_date,
            end=end_date
        )
        self._pairs[direction] = HostpairHistory(response, direction)
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
