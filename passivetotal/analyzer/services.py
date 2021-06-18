from datetime import datetime
from passivetotal.analyzer._common import RecordList, Record, FirstLastSeen, ForPandas, AnalyzerError
from passivetotal.analyzer.ssl import CertHistoryRecord
from passivetotal.analyzer import get_api


class Services(RecordList, ForPandas):

    """Historical port, service and banner data."""

    def _get_shallow_copy_fields(self):
        return ['_totalrecords']
    
    def _get_sortable_fields(self):
        return ['str:firstseen','str:lastseen','duration','port','count','status','protocol']
    
    def _get_dict_fields(self):
        return ['totalrecords']
    
    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalRecords', 0)
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(ServiceRecord(result, self._query))
    
    @property
    def totalrecords(self):
        """Total records available as returned by the API."""
        return self._totalrecords
    
    @property
    def open(self):
        """Only services with port status 'open'.

        :rtype: Services
        """
        return self.filter(status='open')
    
    @property
    def filtered(self):
        """Only services with port status 'filtered'.

        :rtype: Services
        """
        return self.filter(status='filtered')
    
    @property
    def closed(self):
        """Only services with port status 'closed'.

        :rtype: Services
        """
        return self.filter(status='closed')
    


class ServiceRecord(Record, FirstLastSeen, ForPandas):

    """Record of an observed port with current and recent services."""

    def __init__(self, api_response, query=None):
        self._port = api_response.get('portNumber')
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._count = api_response.get('count')
        self._status = api_response.get('status')
        self._protocol = api_response.get('protocol')
        self._banners = api_response.get('banners', [])
        self._currents = api_response.get('currentServices', [])
        self._recents = api_response.get('recentServices', [])
        self._sslcert = api_response.get('mostRecentSslCert')
        self._query = query
    
    def __str__(self):
        return '{0.protocol} {0.port:>5} "{0.status}"'.format(self)
    
    def __repr__(self):
        return "<ServiceRecord {0.protocol} {0.port}>".format(self)

    def _get_dict_fields(self):
        return ['port','count','status','protocol','banners',
                'current_services','recent_services', 'str:firstseen',
                'str:lastseen']
    
    def to_dataframe(self, explode=None):
        """Render this object as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['port','count','status','protocol','banners',
                'current_services','recent_services', 'firstseen',
                'lastseen']
        as_d = { 'query': self._query }
        as_d.update({
            k:getattr(self, k) for k in cols
        })
        cols.insert(0, 'query')
        df = pd.DataFrame([as_d], columns=cols)
        if explode is None:
            return df
        if explode not in ['banners','current_services','recent_services']:
            raise AnalyzerError('Explode param must be banners, current_services or recent_services')
        df_exp = df.explode(explode)
        df_wide = pd.concat([df_exp.drop(explode, axis='columns'), df_exp[explode].apply(pd.Series)], axis='columns')
        return df_wide

    @property
    def port(self):
        """Port number."""
        return self._port
    
    @property
    def count(self):
        """Number of records observed."""
        return self._count
    
    @property
    def status(self):
        """Port status."""
        return self._status
    
    @property
    def is_open(self):
        """Whether the port status is 'open'."""
        return self._status == 'open'
    
    @property
    def protocol(self):
        """Network protocol for the service."""
        return self._protocol
    
    @property
    def is_tcp(self):
        """Whether the protocol is 'TCP'."""
        return self._protocol == 'TCP'
    
    @property
    def is_udp(self):
        """Whether the protocol is 'UDP'."""
        return self._protocol == 'UDP'
    
    @property
    def banners(self):
        """List of banners observed on the service port."""
        return self._banners
    
    @property
    def current_services(self):
        """List of current services."""
        return self._currents
    
    @property
    def recent_services(self):
        """List of recent services."""
        return self._recents
    
    @property
    def certificate(self):
        """SSL Certificate presented by the service.

        :rtype: passivetotal.analyzer.ssl.CertHistoryRecord
        """
        if not self._sslcert:
            return None
        return CertHistoryRecord(self._sslcert)