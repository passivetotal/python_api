from datetime import datetime
import pprint
from passivetotal.analyzer._common import RecordList, Record, FirstLastSeen
from passivetotal.analyzer.ssl import CertHistoryRecord
from passivetotal.analyzer import get_api, get_config


class Services(RecordList):

    def _get_shallow_copy_fields(self):
        return ['_totalrecords']
    
    def _get_sortable_fields(self):
        return ['firstseen','lastseen','duration','port','count','status','protocol']
    
    def parse(self, api_response):
        self._totalrecords = api_response.get('totalRecords')
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(ServiceRecord(result))
    
    @property
    def totalrecords(self):
        return self._totalrecords
    
    @property
    def open(self):
        return self.filter(status='open')
    
    @property
    def filtered(self):
        return self.filter(status='filtered')
    
    @property
    def closed(self):
        return self.fitler(status='closed')
    


class ServiceRecord(Record, FirstLastSeen):

    def __init__(self, api_response):
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
    
    def __str__(self):
        return '{0.protocol} {0.port:>5} "{0.status}"'.format(self)
    
    def __repr__(self):
        return "<ServiceRecord {0.protocol} {0.port}>".format(self)

    @property
    def as_dict(self):
        return {
            field: getattr(self, field) for field in [
                'port','count','status','protocol','banners',
                'current_services','recent_services'
            ]
        }
    
    @property
    def pretty(self):
        config = get_config('pprint')
        return pprint.pformat(self.as_dict, **config)

    @property
    def port(self):
        return self._port
    
    @property
    def count(self):
        return self._count
    
    @property
    def status(self):
        return self._status
    
    @property
    def is_open(self):
        return self._status == 'open'
    
    @property
    def protocol(self):
        return self._protocol
    
    @property
    def is_tcp(self):
        return self._protocol == 'TCP'
    
    @property
    def is_udp(self):
        return self._protocol == 'UDP'
    
    @property
    def banners(self):
        return self._banners
    
    @property
    def current_services(self):
        return self._currents
    
    @property
    def recent_services(self):
        return self._recents
    
    @property
    def certificate(self):
        if not self._sslcert:
            return None
        return CertHistoryRecord(self._sslcert)