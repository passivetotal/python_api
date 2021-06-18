from passivetotal.analyzer._common import AsDictionary, ForPandas



class Summary(AsDictionary, ForPandas):

    """Summary of available PassiveTotal data and key facts for hostnames & IPs."""

    def _count_or_zero(self, field):
        data_summary = self._summary.get('data_summary')
        if data_summary is None:
            return 0
        field_summary = data_summary.get(field)
        if field_summary is None:
            return 0
        return field_summary.get('count', 0)
    
    def __str__(self):
        return "{0.total} records available for {0.name}".format(self)
    
    def __repr__(self):
        return "<{clsname} '{id}'>".format(clsname=self.__class__.__name__, id=self.name)

    def _get_dict_fields(self):
        return ['resolutions','certificates','malware_hashes','projects','articles',
                'total','netblock','os','asn','hosting_provider', 'link', 'links']
    
    def _get_dataset_fields(self):
        return ['resolutions','certificates','malware_hashes','projects','articles']
    
    def to_dataframe(self, exclude_links=True):
        """Render this object as a Pandas DataFrame.

        :param exclude_links: Whether to exclude links from the dataframe (optional, defaults to True)
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        as_d = self.as_dict
        as_d['host'] = self._summary['name']
        cols = ['host','total','articles','certificates','malware_hashes','projects',
                'resolutions','netblock','os','asn']
        if exclude_links:
            del(as_d['link'])
            del(as_d['links'])
        else:
            cols.extend(['link','links'])
        return pd.DataFrame([as_d], columns=cols)
    
    @property
    def available(self):
        """List of datasets with at least one record."""
        return [ field for field in self._get_dataset_fields() if getattr(self, field) > 0 ]
    
    @property
    def total(self):
        """Sum of all available records."""
        return sum([ getattr(self, dataset, 0) for dataset in self._get_dataset_fields() ])

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
        return self._count_or_zero('resolutions')
    
    @property
    def pdns(self):
        """Alias for `resolutions` property."""
        return self.resolutions
    
    @property
    def certificates(self):
        """Count of available SSL certificate historical records."""
        return self._count_or_zero('certificates')
    
    @property
    def malware_hashes(self):
        """Count of available malware hash records."""
        return self._count_or_zero('hashes')
    
    @property
    def projects(self):
        """Count of PassiveTotal projects containing this IP or hostname."""
        return self._count_or_zero('projects')
    
    @property
    def articles(self):
        """Count of open-source intelligence (OSINT) articles referencing this IP or hostname."""
        return self._count_or_zero('articles')
    
    @property
    def link(self):
        """Link to the entire summary card in the UI."""
        return self._summary['link']
    
    @property
    def links(self):
        """Dictionary of links to continue research on a dataset in the UI."""
        summaries = self._summary['data_summary']
        try:
            summaries['malware_hashes'] = summaries['hashes']
        except KeyError:
            pass
        return { name: summary['link'] for name, summary in summaries.items() if name != 'hashes' }
    



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
    
    def _get_dict_fields(self):
        fields = super()._get_dict_fields()
        fields.extend(['trackers','components','hostpairs','cookies'])
        return fields
    
    def _get_dataset_fields(self):
        fields = super()._get_dataset_fields()
        fields.extend(['trackers','components','hostpairs','cookies'])
        return fields

    @property
    def trackers(self):
        """Count of available trackers records for this hostname."""
        return self._count_or_zero('trackers')
    
    @property
    def components(self):
        """Count of available web component records for this hostname."""
        return self._count_or_zero('components')
    
    @property
    def hostpairs(self):
        """Count of available hostpair records for this hostname."""
        return self._count_or_zero('host_pairs')
    
    @property
    def cookies(self):
        """Count of available cookies records for this hostname."""
        return self._count_or_zero('cookies')
    


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
    
    def _get_dict_fields(self):
        fields = super()._get_dict_fields()
        fields.append('services')
        return fields
    
    def _get_dataset_fields(self):
        fields = super()._get_dataset_fields()
        fields.append('services')
        return fields
    
    @property
    def services(self):
        """Number of service (port) history records for this IP."""
        return self._count_or_zero('services')



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