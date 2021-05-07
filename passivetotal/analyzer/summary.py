



class Summary:

    """Summary of available PassiveTotal data and key facts for hostnames & IPs."""

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
    def as_dict(self):
        """All data counts as a mapping."""
        fields = ['resolutions','certificates','malware_hashes','projects','articles']
        return { field: getattr(self, field) for field in fields }
    
    @property
    def available(self):
        """List of datasets with at least one record."""
        return [ field for field, count in self.as_dict.items() if count > 0 ]
    
    @property
    def total(self):
        """Sum of all available records."""
        return sum([ count for count in self.as_dict.values() ])

    @property
    def name(self):
        """Queried name."""
        return self._summary.get('name')

    @property
    def querytype(self):
        """Determined type of the query name."""
        return self._summary.get('type')
    
    @property
    def netblock(self):
        """IP Netblock the host or IP is in."""
        return self._summary.get('netblock')
    
    @property
    def os(self):
        """Operating system of the host."""
        return self._summary.get('os')
    
    @property
    def asn(self):
        """Autonomous System Number the host resides in."""
        return self._summary.get('asn')
    
    @property
    def hosting_provider(self):
        """Name of the web hosting provider."""
        return self._summary.get('hosting_provider')
    
    @property
    def resolutions(self):
        """Count of available pDNS historical resolutions."""
        return self._count_or_none('resolutions')
    
    @property
    def pdns(self):
        """Alias for `resolutions` property."""
        return self.resolutions
    
    @property
    def certificates(self):
        """Count of available SSL certificate historical records."""
        return self._count_or_none('certificates')
    
    @property
    def malware_hashes(self):
        """Count of available malware hash records."""
        return self._count_or_none('hashes')
    
    @property
    def projects(self):
        """Count of PassiveTotal projects containing this IP or hostname."""
        return self._count_or_none('projects')
    
    @property
    def articles(self):
        """Count of open-source intelligence (OSINT) articles referencing this IP or hostname."""
        return self._count_or_none('articles')
    



class HostnameSummary(Summary):

    """Summary of available PassiveTotal data and key facts for hostnames."""

    _instances = {}

    def __new__(cls, api_response):
        hostname = api_response['name']
        self = cls._instances.get(hostname)
        if self is None:
            self = cls._instances[hostname] = object.__new__(HostnameSummary)
            self._summary = api_response
        return self
    
    @property
    def as_dict(self):
        """All data counts as a mapping."""
        counts = super().as_dict
        counts.update({
            field: getattr(self, field) for field in ['trackers','components','hostpairs','cookies']
        })
        return counts

    @property
    def trackers(self):
        """Count of available trackers records for this hostname."""
        return self._count_or_none('trackers')
    
    @property
    def components(self):
        """Count of available web component records for this hostname."""
        return self._count_or_none('components')
    
    @property
    def hostpairs(self):
        """Count of available hostpair records for this hostname."""
        return self._count_or_none('host_pairs')
    
    @property
    def cookies(self):
        """Count of available cookies records for this hostname."""
        return self._count_or_none('cookies')
    


class IPSummary(Summary):

    """Summary of available PassiveTotal data and key facts for IPs."""

    _instances = {}

    def __new__(cls, api_response):
        ip = api_response['name']
        self = cls._instances.get(ip)
        if self is None:
            self = cls._instances[ip] = object.__new__(IPSummary)
            self._summary = api_response
        return self
    
    @property
    def as_dict(self):
        """All data counts as a mapping."""
        counts = super().as_dict
        counts['services'] = self.services
        return counts
    
    @property
    def services(self):
        """Number of service (port) history records for this IP."""
        return self._count_or_none('services')



class HasSummary:
    """An object with summary card data."""

    @property
    def summary(self):
        """Summary of PassiveTotal data available for this hostname.
        
        :rtype: :class:`passivetotal.analyzer.summary.HostnameSummary`
        """
        if getattr(self, '_summary', None) is not None:
            return self._summary
        return self._api_get_summary()