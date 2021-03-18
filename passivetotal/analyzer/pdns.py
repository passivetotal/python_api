from datetime import datetime
from passivetotal.analyzer import get_config
from passivetotal.analyzer._common import RecordList, Record



class PdnsResolutions(RecordList):
    def __init__(self, api_response = None):
        super().__init__(api_response)
        if api_response:
            self._datestart = get_config()['start_date']
            self._dateend = get_config()['end_date']
    
    def _get_shallow_copy_fields(self):
        return ['_queryvalue','_querytype','_pager','_firstseen','_lastseen','_totalrecords','_datestart','_dateend']

    def _get_sortable_fields(self):
        return ['firstseen', 'lastseen', 'duration', 'collected']
    
    def parse(self, api_response):
        self._queryvalue = api_response.get('queryValue')
        self._querytype = api_response.get('queryType')
        self._pager = api_response.get('pager')
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._totalrecords = api_response.get('totalRecords')
        self._records = []
        for result in api_response.get('results',[]):
            self._records.append(PdnsRecord(result))
    
    @property
    def newest(self):
        return self.sorted_by('lastseen', True)[0]
    
    @property
    def oldest(self):
        return self.sorted_by('firstseen')[0]
    
    @property
    def only_a_records(self):
        return self.filter(recordtype='A')
    
    @property
    def only_ips(self):
        return self.filter(resolvetype='ip')
    
    @property
    def only_hostnames(self):
        return self.filter(resolvetype='domain')
    



class PdnsRecord(Record):
    _instances = {}

    def __new__(cls, record):
        recordhash = record['recordHash']
        self = cls._instances.get(recordhash)
        if self is None:
            self = cls._instances[recordhash] = object.__new__(PdnsRecord)
            self._firstseen = record.get('firstSeen')
            self._lastseen = record.get('lastSeen')
            self._sources = record.get('source',[])
            self._value = record.get('value')
            self._collected = record.get('collected')
            self._recordtype = record.get('recordType')
            self._resolve = record.get('resolve')
            self._resolvetype = record.get('resolveType')
            self._rawrecord = record
        return self
    
    def __str__(self):
        days = 'days' if self.duration and self.duration > 1 else 'day'
        return '{0.recordtype:>5} "{0.resolve:>15}" [{0.duration:>4} {1:<4}] ({0.firstseen_date} to {0.lastseen_date})'.format(self, days)
    
    def __repr__(self):
        return "<PdnsRecord '{0.value}' : '{0.resolve}'>".format(self)

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
    
    @property
    def sources(self):
        return self._sources
    
    @property
    def value(self):
        return self._value
    
    @property
    def collected(self):
        if not self._collected:
            return None
        return datetime.fromisoformat(self._collected)
    
    @property
    def recordtype(self):
        return self._recordtype
    
    @property
    def resolve(self):
        return self._resolve
    
    @property
    def resolvetype(self):
        return self._resolvetype
    
    @property
    def ip(self):
        from passivetotal.analyzer import IPAddress
        if self._resolvetype != 'ip':
            return None
        return IPAddress(self._resolve)
    
    @property
    def hostname(self):
        from passivetotal.analyzer import Hostname
        if self._resolvetype != 'domain':
            return None
        return Hostname(self._resolve)
    
    @property
    def rawrecord(self):
        return self._rawrecord
        