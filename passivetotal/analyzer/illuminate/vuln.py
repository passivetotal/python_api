from functools import partial


from passivetotal.analyzer import get_api
from passivetotal.analyzer._common import (
    Record, RecordList, PagedRecordList, FirstLastSeen, ForPandas
)



INDICATOR_PAGE_SIZE = 400

 
    
class AttackSurfaceCVEs(RecordList, PagedRecordList, ForPandas):

    """List of CVEs associated with an attack surface."""

    def __init__(self, attack_surface=None, pagesize=400):
        self._totalrecords = None
        self._attack_surface = attack_surface
        self._records = []
        self._pagination_current_page = 0
        self._pagination_page_size = pagesize
        self._pagination_has_more = True
        if attack_surface is not None:
            self.attack_surface = attack_surface
    
    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_pagination_current_page','_pagination_page_size',
                'attack_surface', '_pagination_callable', '_pagination_has_more']
    
    def _get_sortable_fields(self):
        return ['id','score','observation_count']
    
    def _pagination_parse_page(self, api_response):
        """Parse a page of API response data."""
        self._totalrecords = api_response.get('totalCount')
        if self._pagination_current_page == 0:
            self._records = []
        for result in api_response.get('cves',[]):
            self._records.append(AttackSurfaceCVE(self._attack_surface, result))
    
    @property
    def attack_surface(self):
        """Get the Illuminate Attack Surface associated with this list of CVEs.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.AttackSurface`
        """
        return self._attack_surface
    
    @attack_surface.setter # internal API - necessary for shallow copy operations
    def attack_surface(self, attack_surface):
        self._attack_surface = attack_surface
        if attack_surface.is_own:
            self._pagination_callable = partial(
                get_api('Illuminate').get_asi_vuln_cves
            )
        else:
            self._pagination_callable = partial(
                get_api('Illuminate').get_asi_3p_vuln_cves,
                attack_surface.id
            )



class AttackSurfaceCVE(Record, ForPandas):

    """A record of a CVE associated with an asset in an attack surface."""

    def __init__(self, attack_surface, api_response={}):
        self._attack_surface = attack_surface
        self._cve_id = api_response.get('cveId')
        self._score = api_response.get('priorityScore')
        self._count_observations = api_response.get('observationCount')
        self._link = api_response.get('cveLink')
        self._cwes = api_response.get('cwes',[])
    
    def __str__(self):
        return '{}'.format(self._cve_id)
    
    def __repr__(self):
        return '<AttackSurfaceCVE {0.id}>'.format(self)
    
    def _get_dict_fields(self):
        return ['id','score','observation_count','cwes']
    
    def to_dataframe(self):
        """Render this object as a Pandas dataframe.
        
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['attack_surface', 'cve_id','score','observations','cwes','first_cwe']
        as_d = {
            'attack_surface': self.attack_surface.name,
            'cve_id': self.id,
            'score': self.score,
            'observations': self.observation_count,
            'cwes': len(self.cwes),
            'first_cwe': self.cwes[0]['cweId'],
        }
        return pd.DataFrame.from_records([as_d], columns=cols)
    
    def get_observations(self, pagesize=INDICATOR_PAGE_SIZE):
        """Get a list of observations(assets) vulnerable to this CVE in this attack surface.
        
        :param pagesize: Size of pages to retrieve from the API.
        """
        self._observations = AttackSurfaceCVEObservations(self, pagesize)
        self._observations.load_all_pages()
        return self._observations
    
    @property
    def attack_surface(self):
        """Attack surface this CVE is associated with.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.AttackSurface`
        """
        return self._attack_surface
    
    @property
    def cwes(self):
        """List of CWE IDs for this CVE."""
        return self._cwes
    
    @property
    def id(self):
        """CVE identifier (alias for `cve_id`)."""
        return self._cve_id
    
    @property
    def cve_id(self):
        """CVE identifier."""
        return self._cve_id
    
    @property
    def link(self):
        """API link to get CVE article. 
        
        Consider using the `article` property to access the article directly."""
        return self._link
    
    @property
    def score(self):
        """RiskIQ priority score for this CVE."""
        return self._score
    
    @property
    def observation_count(self):
        """Number of observations (assets) in this attack surface impacted by this vulnerabilty."""
        return self._count_observations
    
    @property
    def observations(self):
        """List of observations (assets) in this attack surface vulnerable to this CVE."""
        if getattr(self, '_observations', None) is not None:
            return self._observations
        return self.get_observations()




class AttackSurfaceCVEObservations(RecordList, PagedRecordList, ForPandas):

    """List of observations (assets) associated with a CVE in a specific attack surface."""

    def __init__(self, cve=None, pagesize=400):
        self._totalrecords = None
        self._cve = cve
        self._records = []
        self._pagination_current_page = 0
        self._pagination_page_size = pagesize
        self._pagination_has_more = True
        if cve is not None:
            self.cve = cve
    
    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_pagination_current_page','_pagination_page_size',
                'cve', '_pagination_callable', '_pagination_has_more']
    
    def _get_sortable_fields(self):
        return ['type','name','firstseen','lastseen']
    
    def _pagination_parse_page(self, api_response):
        """Parse a page of API response data."""
        self._totalrecords = api_response.get('totalCount')
        if self._pagination_current_page == 0:
            self._records = []
        for result in api_response.get('assets',[]):
            self._records.append(AttackSurfaceCVEObservation(self._cve, result))
    
    @property
    def cve(self):
        """Get the CVE associated with this list of observations.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.AttackSurfaceCVE`
        """
        return self._cve
    
    @cve.setter # internal API - necessary for shallow copy operations
    def cve(self, cve):
        self._cve = cve
        if cve.attack_surface.is_own:
            self._pagination_callable = partial(
                get_api('Illuminate').get_asi_vuln_cve_observations,
                cve.id
            )
        else:
            self._pagination_callable = partial(
                get_api('Illuminate').get_asi_3p_vuln_cve_observations,
                cve.attack_surface.id,
                cve.id
            )



class AttackSurfaceCVEObservation(Record, FirstLastSeen, ForPandas):

    """An observation (asset) vulnerable to a specific CVE in a given attack surface."""

    def __init__(self, cve, api_response={}):
        self._cve = cve
        self._type = api_response.get('type')
        self._name = api_response.get('name')
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
    
    def __str__(self):
        return '{}'.format(self._name)
    
    def __repr__(self):
        return '<AttackSurfaceCVEObservation {0.type}:{0.name}>'.format(self)
    
    def _get_dict_fields(self):
        return ['cve_id','type','name','str:firstseen','str:lastseen']
    
    def to_dataframe(self):
        """Render this object as a Pandas dataframe.
        
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['attack_surface','cve_id','type','name','firstseen','lastseen']
        as_d = {
            'attack_surface': self.attack_surface.name,
            'cve_id': self.cve.id,
            'type': self.type,
            'name': self.name,
            'firstseen': self.firstseen,
            'lastseen': self.lastseen,
        }
        return pd.DataFrame.from_records([as_d], columns=cols)
    
    @property
    def attack_surface(self):
        """Attack surface this observation is associated with.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.AttackSurface`
        """
        return self.cve.attack_surface
    
    @property
    def cve(self):
        """CVE this observation is vulnerable to, in the context of a specific attack surface.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.AttackSurfaceCVE`
        """
        return self._cve
    
    @property
    def type(self):
        """Type of this observation (asset)."""
        return self._type
    
    @property
    def name(self):
        """Name of this observation (asset)."""
        return self._name
    


class AttackSurfaceComponents(RecordList, PagedRecordList, ForPandas):

    """List of vulnerable components (detections) associated with an attack surface."""

    def __init__(self, attack_surface=None, pagesize=400):
        self._totalrecords = None
        self._attack_surface = attack_surface
        self._records = []
        self._pagination_current_page = 0
        self._pagination_page_size = pagesize
        self._pagination_has_more = True
        if attack_surface is not None:
            self.attack_surface = attack_surface
    
    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_pagination_current_page','_pagination_page_size',
                'attack_surface', '_pagination_callable', '_pagination_has_more']
    
    def _get_sortable_fields(self):
        return ['type','name','severity','count']
    
    def _pagination_parse_page(self, api_response):
        """Parse a page of API response data."""
        self._totalrecords = api_response.get('totalCount')
        if self._pagination_current_page == 0:
            self._records = []
        for result in api_response.get('vulnerableComponents',[]):
            self._records.append(AttackSurfaceComponent(self._attack_surface, result))
    
    @property
    def attack_surface(self):
        """Get the CVE associated with this list of observations.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.AttackSurface`
        """
        return self._attack_surface
    
    @attack_surface.setter # internal API - necessary for shallow copy operations
    def attack_surface(self, attack_surface):
        self._attack_surface = attack_surface
        if attack_surface.is_own:
            self._pagination_callable = partial(
                get_api('Illuminate').get_asi_vuln_components
            )
        else:
            self._pagination_callable = partial(
                get_api('Illuminate').get_asi_3p_vuln_components,
                attack_surface.id
            )



class AttackSurfaceComponent(Record, FirstLastSeen, ForPandas):

    """A vulnerable component (detection) observed in an attack surface."""

    def __init__(self, attack_surface, api_response={}):
        self._attack_surface = attack_surface
        self._type = api_response.get('type')
        self._name = api_response.get('name')
        self._severity = api_response.get('severity')
        self._count = api_response.get('count')
    
    def __str__(self):
        return '{}'.format(self._name)
    
    def __repr__(self):
        return '<AttackSurfaceComponent {0.type}:{0.name}>'.format(self)
    
    def _get_dict_fields(self):
        return ['vendor_id','type','name','severity','count']
    
    def to_dataframe(self):
        """Render this object as a Pandas dataframe.
        
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['attack_surface','type','name','severity','count']
        as_d = {
            'attack_surface': self.attack_surface.name,
            'type': self.type,
            'name': self.name,
            'severity': self.severity,
            'count': self.count,
        }
        return pd.DataFrame.from_records([as_d], columns=cols)
    
    @property
    def attack_surface(self):
        """Attack surface this component is associated with.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.AttackSurface`
        """
        return self._attack_surface
    
    @property
    def type(self):
        """Type of this component (detection)."""
        return self._type
    
    @property
    def name(self):
        """Name of this component (detection)."""
        return self._name
    
    @property
    def severity(self):
        """Severity of this detection."""
        return self._severity
    
    @property
    def count(self):
        """Count."""
        return self._count