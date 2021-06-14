from datetime import datetime
import pprint
from passivetotal.analyzer._common import (
    RecordList, Record, FirstLastSeen, PagedRecordList, ForPandas
)
from passivetotal.analyzer import get_api, get_config



class CookieHistory(RecordList, PagedRecordList, ForPandas):

    """Historical cookie data."""

    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_query']
    
    def _get_sortable_fields(self):
        return ['firstseen','lastseen','name','domain']
    
    def _get_dict_fields(self):
        return ['totalrecords']
    
    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalRecords', 0)
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(CookieRecord(result, self._query))
    
    @property
    def as_dict(self):
        d = super().as_dict
        d.update({
            'distinct_domains': list(self.domains),
            'distinct_names': list(self.names),
        })
        return d
    
    @property
    def domains(self):
        """Set of unique cookie domains in the record list."""
        return set([cookie.domain for cookie in self if cookie.domain is not None])
    
    @property
    def names(self):
        """Set of unique cookie names in the record list."""
        return set([cookie.name for cookie in self if cookie.name is not None])



class CookieRecord(Record, FirstLastSeen, ForPandas):

    """Record of an observed cookie."""

    def __init__(self, api_response, query):
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._cookieDomain = api_response.get('cookieDomain')
        self._cookieName = api_response.get('cookieName')
        self._hostname = api_response.get('hostname')
        self._query = query
    
    def __str__(self):
        return '"{0.name}" @ {0.domain} ({0.firstseen_date} to {0.lastseen_date})'.format(self)

    def __repr__(self):
        return '<CookieRecord {0.name}>'.format(self)

    def _get_dict_fields(self):
        return ['domain','str:firstseen','str:lastseen','name','hostname']
    
    def to_dataframe(self):
        """Render this object as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['firstseen','lastseen','domain','name','hostname']
        as_d = {
            f: getattr(self, f) for f in cols
        }
        as_d['query'] = self._query
        cols.insert(0, 'query')
        return pd.DataFrame([as_d], columns=cols)
    
    @property
    def domain(self):
        """Cookie domain name."""
        return self._cookieDomain

    @property
    def hostname(self):
        """Hostname where this cookie was observed."""
        return self._hostname
    
    @property
    def name(self):
        """Cookie name; alias of `CookieRecord.value`."""
        return self._cookieName
    
    @property
    def value(self):
        """Cookie name."""
        return self._cookieName

    

class HasCookies:

    """An object with cookie history."""

    def _api_get_cookies(self, start_date=None, end_date=None):
        """Query the host attributes API for cookie history.
        
        Only the first page of results is returned; pagination is not
        supported. Check the totalrecords attribute of the response object
        to determine if more records are available.
        """
        query=self.get_host_identifier()
        response = get_api('HostAttributes').get_cookies(
            query=query,
            start=start_date,
            end=end_date
        )
        self._cookies = CookieHistory(response, query=query)
        return self._cookies

    @property
    def cookies(self):
        """History of cookies presented by this host.

        :rtype: :class:`passivetotal.analyzer.components.CookieHistory`
        """
        if getattr(self, '_cookies', None) is not None:
            return self._cookies
        config = get_config()
        return self._api_get_cookies(
            start_date=config['start_date'],
            end_date=config['end_date']
        )

