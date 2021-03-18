from datetime import datetime



class RecordList:
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
        copy = self.__class__()
        for field in self._get_shallow_copy_fields():
            setattr(copy,field,getattr(self, field))
        return copy
    
    def _get_shallow_copy_fields(self):
        raise NotImplemented

    def _get_sortable_fields(self):
        raise NotImplemented
    
    def parse(self, api_response):
        raise NotImplemented
    
    @property
    def all(self):
        return self._records
    
    def filter(self, **kwargs):
        return self.filter_and(**kwargs)
    
    def filter_and(self, **kwargs):
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.match_all(**kwargs), self._records)
        return filtered_results
    
    def filter_or(self, **kwargs):
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.match_any(**kwargs), self._records)
        return filtered_results
    
    def sorted_by(self, field, reverse=False):
        if field not in self._get_sortable_fields():
            raise ValueError('Cannot sort on {}'.format(field))
        sorted_results = self._make_shallow_copy()
        sorted_results._records = sorted(self.all, key=lambda record: getattr(record, field), reverse=reverse)
        return sorted_results



class Record:
    
    def match_all(self, **kwargs):
        matches_one = False
        for prop, value in kwargs.items():
            if getattr(self, prop) == value:
                matches_one = True
            else:
                return False
        return matches_one

    def match_any(self, **kwargs):
        for prop, value in kwargs.items():
            if getattr(self, prop) == value:
                return True
        return False



class FirstLastSeen:

    @property
    def firstseen(self):
        if not self._firstseen:
            return None
        return datetime.fromisoformat(self._firstseen)
    
    @property
    def firstseen_date(self):
        return self.firstseen.date()
    
    @property
    def firstseen_raw(self):
        return self._firstseen
    
    @property
    def lastseen(self):
        if not self._lastseen:
            return None
        return datetime.fromisoformat(self._lastseen)
    
    @property
    def lastseen_date(self):
        return self.lastseen.date()
    
    @property
    def lastseen_raw(self):
        return self._lastseen
    
    @property
    def duration(self):
        if not self._firstseen or not self._lastseen:
            return None
        interval = self.lastseen - self.firstseen
        return interval.days