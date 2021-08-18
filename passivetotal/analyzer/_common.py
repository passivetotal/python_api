"""Base classes and common methods for the analyzer package."""
from datetime import datetime
import pprint
import re

try:
    import pandas
    PANDAS = True
except ImportError:
    PANDAS = False



def is_ip(test):
    """Test to see if a string contains an IPv4 address."""
    pattern = re.compile(r"^(\d{1,3}(?:\.|\]\.\[|\[\.\]|\(\.\)|{\.})\d{1,3}(?:\.|\]\.\[|\[\.\]|\(\.\)|{\.})\d{1,3}(?:\.|\]\.\[|\[\.\]|\(\.\)|{\.})\d{1,3})$")
    return len(pattern.findall(test)) > 0

def refang(host):
    """Remove square braces around dots in a host."""
    return re.sub(r'[\[\]]','', host)



class AsDictionary:
    """An object that can represent itself as a dictionary."""
    
    def _get_dict_fields(self):
        """Implementations may return a list of record list attributes to include in
        a dictionary representation of this list.
        
        Prefix fields with `str:` to have the value wrapped in str().
        """
        return []
    
    @property
    def as_dict(self):
        """Return a dictionary representation of the object."""
        plain_fields = [ field for field in self._get_dict_fields() if ':' not in field ]
        typed_fields = [ field for field in self._get_dict_fields() if ':' in field ]
        d = { field: getattr(self, field) for field in plain_fields }
        for field in typed_fields:
            (type, name) = field.split(':')
            if type == 'str':
                value = getattr(self, name)
                if isinstance(value, list):
                    d[name] = [ str(v) for v in value ]
                elif value is None:
                    d[name] = None
                else:
                    d[name] = str(value)
        return d
    
    @property
    def pretty(self):
        """Pretty printed version of this object's dictionary representation."""
        from passivetotal.analyzer import get_config
        config = get_config('pprint')
        return pprint.pformat(self.as_dict, **config)



class ForPandas:

    """Object designed to work with the pandas data analysis library."""

    def _get_pandas(self):
        """Get a reference to the pandas module.

        Throws `AnalyzerMissingModule` if pandas is not installed.
        """
        if not PANDAS:
            raise AnalyzerMissingModule('Missing "pandas" Python module')
        return pandas

    def to_dataframe(self, **kwargs):
        """Render this object as a Pandas DataFrame.

        Implementations may add additional keywords to customize building the data structure.

        Default implementation tries to iterate through self and calls to_dataframe on
        each record with the same parameters passed to this method. If that fails (usually
        because self isn't iterable), it uses the as_dict param of self.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        try:
            if len(self) == 0:
                return pd.DataFrame()
            return pd.concat([ r.to_dataframe(**kwargs) for r in self], ignore_index=True)
        except TypeError:
            return pd.DataFrame([self.as_dict])
    
    @property
    def as_df(self):
        """Get this object as a Pandas DataFrame.

        Use `to_dataframe()' instead if you need to control how the dataframe is built.

        Requires the pandas Python library. Throws `AnalyzerError` if it is missing.
        :rtype: :class:`pandas.DataFrame`
        """
        return self.to_dataframe()


class RecordList(AsDictionary):

    """List-like object that contains a set of records."""

    def __init__(self, api_response = None, query=None):
        self._query = query
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
        return NotImplemented

    def _get_sortable_fields(self):
        """Implementations must return a list of object attribues that are sortable."""
        return NotImplemented
    
    def parse(self, api_response):
        """Implementations must accept an API response and populate themselves 
        with a list of the correct record types."""
        return NotImplemented
    
    @property
    def all(self):
        """All the records as a list."""
        return self._records
    
    @property
    def as_dict(self):
        """Return the recordlist as a list of dictionary objects."""
        d = super().as_dict
        d['records'] = [ r.as_dict for r in self.all ]
        return d
    
    def filter(self, **kwargs):
        """Shortcut for filter_and."""
        return self.filter_and(**kwargs)
    
    @property
    def length(self):
        return len(self.all)
    
    def filter_fn(self, fn):
        """Return only records where a function returns true."""
        filtered_results = self._make_shallow_copy()
        filtered_results._records = list(filter(fn, self.all))
        return filtered_results

    def filter_and(self, **kwargs):
        """Return only records that match all key/value arguments."""
        return self.filter_fn(lambda r: r.match_all(**kwargs))
    
    def filter_or(self, **kwargs):
        """Return only records that match any key/value arguments."""
        return self.filter_fn(lambda r: r.match_any(**kwargs))
    
    def filter_in(self, **kwargs):
        """Return only records where a field contains one or more values.
        
        Usage: 
          filter_in(fieldname=['value1','value2']) or
          filter_in(fieldname='value1,value2)
        """
        field, values = kwargs.popitem()
        if isinstance(values, str):
            values = values.split(',')
        return self.filter_fn(lambda r: getattr(r, field) in values)
    
    def filter_substring(self, **kwargs):
        """Return only records where a case-insensitive match on the field returns true."""
        field, value = kwargs.popitem()
        return self.filter_fn(lambda r: value.casefold() in getattr(r, field).casefold())
    
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

    def _ensure_firstlastseen(self):
        """Ensure this record list has records of type FirstLastSeen."""
        if not isinstance(self.all[0], FirstLastSeen):
            raise TypeError('Cannot filter on a record type without firstseen / lastseen fields')
    
    def filter_dateseen_after(self, date_string):
        self._ensure_firstlastseen()
        dateobj = datetime.fromisoformat(date_string)
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.firstseen > dateobj, self.all)
        return filtered_results

    def filter_dateseen_before(self, date_string):
        self._ensure_firstlastseen()
        dateobj = datetime.fromisoformat(date_string)
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.lastseen < dateobj, self.all)
        return filtered_results
    
    def filter_dateseen_between(self, start_date_string, end_date_string):
        self._ensure_firstlastseen()
        dateobj_start = datetime.fromisoformat(start_date_string)
        dateobj_end = datetime.fromisoformat(end_date_string)
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.firstseen >= dateobj_start and r.lastseen <= dateobj_end, self.all)
        return filtered_results



class Record(AsDictionary):

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

    """Record list that may return more than one page of data."""

    def _pagination_get_api_callable(self):
        """Get a callable that can be used to retrieve a page of API results.
        
        Default implementation returns `self._pagination_callable`.
        """
        return self._pagination_callable

    def _pagination_get_api_results(self, page):
        """Get a page of results from the API.
        
        Default implementation calls `self._pagination_get_api_callable`
        with `page` param set to `page`.
        
        :param page: Page of results to retrieve from the API.
        """
        return self._pagination_get_api_callable()(page=page)
    
    def _pagination_get_current_page(self):
        """Return the current page of results.

        Default implementation returns `self._pagination_current_page`.
        """
        return self._pagination_current_page
    
    def _pagination_get_page_size(self):
        """Return the page size used in API queries.

        Default implementation returns `self._pagination_page_size`.
        """
        return self._pagination_page_size
    
    def _pagination_increment_page(self):
        """Increment the page number.

        Default implementation acts on `self._pagination_current_page`.
        """
        self._pagination_current_page = self._pagination_current_page + 1
    
    def _pagination_parse_page(self, results):
        """Parse a page of results from the API."""
        return NotImplemented
    
    def load_next_page(self):
        """Load the next page of results from the API.
        
        Throws `AnalyzerError` when `has_more_records` is False.
        """
        has_more = getattr(self, '_pagination_has_more', False)
        if not has_more:
            raise AnalyzerError('No more pages available for this API query.')
        page = self._pagination_get_current_page()
        results = self._pagination_get_api_results(page)
        self._pagination_parse_page(results)
        self._pagination_increment_page()
        self._pagination_has_more = len(self) < self.totalrecords
     
    def load_all_pages(self):
        """Load all pages of results from the API."""
        while self.has_more_records:
            self.load_next_page()

    @property
    def totalrecords(self):
        """Total number of available records as reported by the API."""
        return self._totalrecords
    
    @property
    def has_more_records(self):
        """Whether more records are available.

        :rtype: bool
        """
        return self._pagination_has_more



class FilterDomains:

    """Object that supports filtering records against a list of hostnames, registered domains, or tlds.
    
    Expects a `filter_fn` method on `self` and for each record to expose a `host` property.
    """

    def _get_object(self, input):
        """Wrapper for `analyzer.get_object` to avoid circular imports."""
        from . import get_object
        return get_object(input)

    def exclude_hosts_in(self, hosts):
        """Filter the list to exclude records where the parent or child is contained in not in 
        a list of hosts. Accepts either a list of strings or a list of `analyzer.Hostname` objects.
        
        Will apply to parents if `direction` is parents (from `hostpair_parents` property) or to
        children if `direction` is children(from `hostpair_children` property).

        Use `exclude_domains_in()` to match against only the registered domain.
        
        :param hosts: List of hostnames to directly match against, as a comma-separated string or a list.
        """
        if isinstance(hosts, str):
            hosts = hosts.split(',')
        return self.filter_fn(lambda h:  h.host not in [self._get_object(h) for h in hosts])
    
    def exclude_domains_in(self, hosts):
        """Filter the list to exclude records where the registered domain of the parent or child 
        is not in a list of hosts. Accepts either a list of strings or a list of 
        `analyzer.Hostname` objects.
        
        Will apply to parents if `direction` is parents (from `hostpair_parents` property) or to
        children if `direction` is children(from `hostpair_children` property).
        
        :param hosts: List of hostnames to directly match against, as a comma-separated string or a list.
        """
        if isinstance(hosts, str):
            hosts = hosts.split(',')
        return self.filter_fn(
            lambda h: h.host.registered_domain not in [
                h.registered_domain for h in [self._get_object(host) for host in hosts] if h.is_hostname
            ] if h.host.is_hostname else False
        )
    
    def exclude_tlds_in(self, tlds):
        """Filter the list to exclude records where the tld of the registered domain of the 
        parent or child is not in a list of tlds. Accepts either a list of strings or a list of 
        `analyzer.Hostname` objects.
        
        Will apply to parents if `direction` is parents (from `hostpair_parents` property) or to
        children if `direction` is children(from `hostpair_children` property).
        
        :param hosts: List of hostnames to directly match against, as a comma-separated string or a list.
        """
        if isinstance(tlds, str):
            tlds = tlds.split(',')
        return self.filter_fn(
            lambda h: h.host.tld not in tlds if h.host.is_hostname else False
        )
                   


class AnalyzerError(Exception):
    """Base error class for Analyzer objects."""
    pass



class AnalyzerAPIError(AnalyzerError):
    """Raised when the API reports an error condition."""
    
    def __init__(self, response):
        self.response = response
        self.status_code = response.status_code
        try:
            self.url = response.request.url
        except Exception:
            self.url = 'unknown url'
        try:
            self.json = self.response.json()
        except Exception:
            self.json = {}
        if self.json is None:
            self.message = 'No JSON data in API response'
        else:
            try:
                self.message = self.json.get('error', self.json.get('message', str(response)))
            except Exception:
                self.message = ''
    
    def __str__(self):
        return 'Error #{0.status_code} "{0.message}" ({0.url})'.format(self)



class AnalyzerMissingModule(AnalyzerError):
    """Raised when a necessary module is missing."""
    pass