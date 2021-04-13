"""Base classes and common methods for the analyzer package."""



from datetime import datetime



class RecordList:

    """List-like object that contains a set of records."""

    def __init__(self, api_response = None):
        self._records = []
        if api_response:
            self.parse(api_response)
    
    def __iter__(self):
        for r in self._records:
            yield r
    
    def __getitem__(self, key):
        return self._records[key]
    
    def __len__(self):
        return len(self._records)
    
    def _make_shallow_copy(self):
        """Creates a shallow copy of the instance."""
        copy = self.__class__()
        for field in self._get_shallow_copy_fields():
            setattr(copy,field,getattr(self, field))
        return copy
    
    def _get_shallow_copy_fields(self):
        """Implementations must return a list of fields to copy into new instances."""
        raise NotImplemented

    def _get_sortable_fields(self):
        """Implementations must return a list of object attribues that are sortable."""
        raise NotImplemented
    
    def parse(self, api_response):
        """Implementations must accept an API response and populate themselves 
        with a list of the correct record types."""
        raise NotImplemented
    
    @property
    def all(self):
        """All the records as a list."""
        return self._records
    
    def filter(self, **kwargs):
        """Shortcut for filter_and."""
        return self.filter_and(**kwargs)
    
    def filter_and(self, **kwargs):
        """Return only records that match all key/value arguments."""
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.match_all(**kwargs), self._records)
        return filtered_results
    
    def filter_or(self, **kwargs):
        """Return only records that match any key/value arguments."""
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.match_any(**kwargs), self._records)
        return filtered_results
    
    def sorted_by(self, field, reverse=False):
        """Return a sorted list.
        
        :param field: name of the attribute to sort on
        :param reverse: whether to sort in reverse order.
        """
        if field not in self._get_sortable_fields():
            raise ValueError('Cannot sort on {}'.format(field))
        sorted_results = self._make_shallow_copy()
        sorted_results._records = sorted(self.all, key=lambda record: getattr(record, field), reverse=reverse)
        return sorted_results



class Record:

    """A Record in a :class:`RecordList`."""
    
    def match_all(self, **kwargs):
        """Whether attributes of this record match all the key/value arguments."""
        matches_one = False
        for prop, value in kwargs.items():
            if getattr(self, prop) == value:
                matches_one = True
            else:
                return False
        return matches_one

    def match_any(self, **kwargs):
        """Whether attributes of this record match any of the key/value arguments."""
        for prop, value in kwargs.items():
            if getattr(self, prop) == value:
                return True
        return False



class FirstLastSeen:

    """Base class for Records with first-seen and last-seen dates.

    Expects _firstseen and _lastseen attributes to exist on the instance.

    """

    @property
    def firstseen(self):
        """Date & time the record was first seen.

        :rtype: datetime
        """
        if not self._firstseen:
            return None
        return datetime.fromisoformat(self._firstseen)
    
    @property
    def firstseen_date(self):
        """Date record was first seen.

        :rtype: date
        """
        return self.firstseen.date()
    
    @property
    def firstseen_raw(self):
        """Raw firstseen value returned by the API."""
        return self._firstseen
    
    @property
    def lastseen(self):
        """Date & time the record was most recently observed.
        
        :rtype: datetime
        """
        if not self._lastseen:
            return None
        return datetime.fromisoformat(self._lastseen)
    
    @property
    def lastseen_date(self):
        """Date the record was most recently observed.

        :rtype: date
        """
        return self.lastseen.date()
    
    @property
    def lastseen_raw(self):
        """Raw lastseen value returned by the API."""
        return self._lastseen
    
    @property
    def duration(self):
        """Length of time record was observed, in days.

        Calculates the timedelta between firstseen and lastseen.

        :rtype: int
        """
        if not self._firstseen or not self._lastseen:
            return None
        interval = self.lastseen - self.firstseen
        return interval.days



class PagedRecordList:

    """Record list that may return more than one page of data.

    Current implementation only provides a mechanism to determine if
    more records are available. Actual pagination is not implemented yet.
    
    Expects a _totalrecords attribute on the object
    """

    @property
    def totalrecords(self):
        """Total number of available records as reported by the API."""
        return self._totalrecords
    
    @property
    def has_more_records(self):
        """Whether more records are available.

        :rtype: bool
        """
        return len(self) < self._totalrecords

