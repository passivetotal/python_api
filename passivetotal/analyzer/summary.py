from passivetotal.analyzer import get_config



class Summary:

    def _count_or_none(self, field):
        data_summary = self._summary.get('data_summary')
        if not data_summary:
            return None
        field_summary = data_summary.get(field)
        if not field_summary:
            return None
        return field_summary.get('count')
    
    def __str__(self):
        return "{0.total} records available for {0.name}".format(self)
    
    def __repr__(self):
        return "<{clsname} '{id}'>".format(clsname=self.__class__.__name__, id=self.name)

    @property
    def all(self):
        fields = ['resolutions','certificates','malware_hashes','projects','articles']
        return { field: getattr(self, field) for field in fields }
    
    @property
    def available(self):
        return [ field for field, count in self.all.items() if count > 0 ]
    
    @property
    def total(self):
        return sum([ count for count in self.all.values() ])

    @property
    def name(self):
        return self._summary.get('name')

    @property
    def querytype(self):
        return self._summary.get('type')
    
    @property
    def netblock(self):
        return self._summary.get('netblock')
    
    @property
    def os(self):
        return self._summary.get('os')
    
    @property
    def asn(self):
        return self._summary.get('asn')
    
    @property
    def hosting_provider(self):
        return self._summary.get('hosting_provider')
    
    @property
    def resolutions(self):
        return self._count_or_none('resolutions')
    
    @property
    def pdns(self):
        return self.resolutions
    
    @property
    def certificates(self):
        return self._count_or_none('certificates')
    
    @property
    def malware_hashes(self):
        return self._count_or_none('hashes')
    
    @property
    def projects(self):
        return self._count_or_none('projects')
    
    @property
    def articles(self):
        return self._count_or_none('articles')
    



class HostnameSummary(Summary):
    _instances = {}

    def __new__(cls, api_response):
        hostname = api_response['name']
        self = cls._instances.get(hostname)
        if self is None:
            self = cls._instances[hostname] = object.__new__(HostnameSummary)
            self._summary = api_response
        return self
    
    @property
    def all(self):
        counts = super().all
        counts.update({
            field: getattr(self, field) for field in ['trackers','components','hostpairs','cookies']
        })
        return counts

    @property
    def trackers(self):
        return self._count_or_none('trackers')
    
    @property
    def components(self):
        return self._count_or_none('components')
    
    @property
    def hostpairs(self):
        return self._count_or_none('host_pairs')
    
    @property
    def cookies(self):
        return self._count_or_none('cookies')
    


class IPSummary(Summary):
    _instances = {}

    def __new__(cls, api_response):
        ip = api_response['name']
        self = cls._instances.get(ip)
        if self is None:
            self = cls._instances[ip] = object.__new__(IPSummary)
            self._summary = api_response
        return self
    
    @property
    def all(self):
        counts = super().all
        counts['services'] = self.services
        return counts
    
    @property
    def services(self):
        return self._count_or_none('services')
    