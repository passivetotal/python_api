from collections import OrderedDict
from functools import lru_cache, partial

from urllib.parse import parse_qsl

from passivetotal.analyzer import get_api, get_object
from passivetotal.analyzer._common import (
    Record, RecordList, PagedRecordList, FirstLastSeen,
    ForPandas, AnalyzerError
)



INDICATOR_PAGE_SIZE = 400



class AttackSurfaces(RecordList, PagedRecordList, ForPandas):

    """List of RiskIQ Illuminate Attack Surfaces.
    
    Primarily used for enumerating a set of third-party vendors.
    """

    def __init__(self, pagesize=INDICATOR_PAGE_SIZE):
        self._totalrecords = None
        self._pagination_current_page = 0
        self._pagination_page_size = pagesize
        self._pagination_has_more = True
        self._records = []
        self._pagination_callable = partial(
            get_api('Illuminate').get_asi_3p_vendors,
            size=pagesize
        )
    
    def __getitem__(self, key):
        if isinstance(key, str):
            filtered = self.filter(id=key)
            if len(filtered) != 1:
                raise KeyError('No profile found for id {}'.format(key))
            return filtered[0]
        return super().__getitem__(key)
    
    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_pagination_current_page','_pagination_page_size',
                '_pagination_callable', '_pagination_has_more']
    
    def _get_sortable_fields(self):
        return ['id','name','is_own','is_third_party','high_observation_count',
                'medium_observation_count','low_observation_count']
    
    def _get_dict_fields(self):
        return ['totalrecords']
    
    def _pagination_parse_page(self, api_response):
        """Parse a page of API response data."""
        self._totalrecords = api_response.get('totalCount')
        if self._pagination_current_page == 0:
            self._records = []
        for result in api_response.get('vendors', []):
            result['own'] = False
            self._records.append(AttackSurface(api_response=result))
    
    @staticmethod
    @lru_cache(maxsize=None)
    def load(pagesize=INDICATOR_PAGE_SIZE):
        """Get a list of all third-party (vendor) attack surfaces authorized for this API account.
        
        :param pagesize: Size of pages to retrieve from the API (optional).
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurfaces`.
        """
        attack_surfaces = AttackSurfaces(pagesize)
        attack_surfaces.load_all_pages()
        return attack_surfaces



class AttackSurface(Record, ForPandas):

    """RiskIQ Illuminate Attack Surface Intelligence."""

    _instances = {}
    _LEVELS = ['high','medium','low']

    def __new__(cls, id=None, api_response=None):
        if id is None and api_response is not None and 'id' in api_response:
            id = api_response.get('id')
        if id is not None:
            self = cls._instances.get(id)
            if self is not None:
                return self
        self = cls._instances[id] = object.__new__(cls)
        self._insights = { l:None for l in ['high','medium','low'] }
        if api_response is not None:
            self._parse(api_response)
        return self
    
    def __str__(self):
        return self.name
    
    def __repr__(self):
        id = getattr(self, '_id', None)
        name = getattr(self, '_name', None)
        return '<AttackSurface #{0} "{1}">'.format(id, name)
    
    def _get_dict_fields(self):
        return ['id','name','is_own','is_third_party','high_priority_observation_count',
                'medium_priority_observation_count','low_priority_observation_count']
    
    def _parse(self, api_response):
        self._id = api_response.get('id')
        self._name = api_response.get('name')
        self._is_own = api_response.get('own')
        self._priorities_raw = api_response.get('priorities')
    
    def _ensure_valid_level(self, level):
        if level not in self._LEVELS:
            raise ValueError('Level must be one of {}'.format(self._LEVELS))
    
    @staticmethod
    def load(id=None):
        if id is None:
            response = get_api('Illuminate').get_asi_summary()
            response['own'] = True
        else:
            response = get_api('Illuminate').get_asi_3p_vendor_summary(id)
            response['own'] = False
        return AttackSurface(api_response=response)
    
    @staticmethod
    @lru_cache(typed=True, maxsize=10)
    def find(id_or_name=None):
        """Find one attack surface.
        
        Call with no parameters to find your Attack Surface.
        Pass a number to load a specific Attack Surface by ID, or pass a string to load the entire
        list of Attack Surfaces and search them by case-insensitive substring.
        
        Raises `AnalyzerError` if no attack surfaces are found or if more than one Attack Surface name
        matches the parameter.
        
        :returns: :class:`passivetotal.illuminate.asi.AttackSurface`
        """
        if id_or_name is None:
            return AttackSurface.load()
        if isinstance(id_or_name, int):
            return AttackSurface.load(id_or_name)
        all_asi = AttackSurfaces.load()
        filtered_asi = all_asi.filter_substring(name=id_or_name)
        if len(filtered_asi) == 0:
            raise AnalyzerError('No attack surfaces found that match that name.')
        if len(filtered_asi) > 1:
            raise AnalyzerError('More than one attack surface was found - try a more specific name')
        return filtered_asi[0]

    def get_insights(self, level):
        """Get insights at a level (high, medium or low).
        
        :param level: Priority level (high, medium, or low).
        :returns: List of :class:`AttackSurfaceInsights`
        """
        self._ensure_valid_level(level)
        if self._insights[level] is not None:
            return self._insights[level]
        self._insights[level] = AttackSurfaceInsights.load(self, level)
        return self._insights[level]
    
    def get_observation_count(self, level):
        """Get number of insights with impacted assets (observations) at a given level.
        
        :param level: Priority level (high, medium, or low).
        :rtype: int Count of insights with observations
        """
        self._ensure_valid_level(level)
        return self._priorities_raw[level]['observationCount']
    
    def get_cves(self, pagesize=INDICATOR_PAGE_SIZE):
        """Get a list of CVEs impacting assets in this attack surface.
        
        :param pagesize: Size of pages to retrieve from the API.
        """
        from passivetotal.analyzer.illuminate import AttackSurfaceCVEs
        self._cves = AttackSurfaceCVEs(self, pagesize)
        self._cves.load_all_pages()
        return self._cves

    def get_components(self, pagesize=INDICATOR_PAGE_SIZE):
        """Get a list of vulnerable components (detections) in this attack surface.
        
        :param pagesize: Size of pages to retrieve from the API.
        """
        from passivetotal.analyzer.illuminate import AttackSurfaceComponents
        self._components = AttackSurfaceComponents(self, pagesize)
        self._components.load_all_pages()
        return self._components
    
    def to_dataframe(self):
        """Render this object as a Pandas DataFrame.
        
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['name','is_own','is_third_party','high_priority_observation_count',
                'medium_priority_observation_count','low_priority_observation_count']
        as_d = OrderedDict()
        as_d['asi_id'] = self.id
        for col in cols:
            as_d[col] = getattr(self, col)
        return pd.DataFrame.from_records([as_d])

    @property
    def all_insights(self):
        """All insights across all levels (high, medium, and low).
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceInsights`
        """
        insights = self.high_priority_insights._make_shallow_copy()
        insights._level = 'ALL'
        insights._records = []
        for level in self._LEVELS:
            insights._records.extend(self.get_insights(level)._records)
        return insights
    
    @property
    def all_active_insights(self):
        """All insights with active observations across all levels.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceInsights`
        """
        return self.all_insights.only_active_insights

    @property
    def id(self):
        return self._id

    @property
    def is_own(self):
        """Whether this attack surface represents the org associated with the API credentials."""
        return self._is_own
    
    @property
    def is_third_party(self):
        """Whether this is a third-party attack surface."""
        return not self._is_own
    
    @property
    def name(self):
        return self._name
    
    @property
    def high_priority_observation_count(self):
        """Number of high-priority insights with impacted assets (observations)."""
        return self.get_observation_count('high')
    
    @property
    def medium_priority_observation_count(self):
        """Number of medium-priority insights with impacted assets (observations)."""
        return self.get_observation_count('medium')
    
    @property
    def low_priority_observation_count(self):
        """Number of low-priority insights with impacted assets (observations)."""
        return self.get_observation_count('low')

    @property
    def high_priority_insights(self):
        """Get high priority insights.
        
        :rtype: List of :class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceInsights`
        """
        return self.get_insights('high')
    
    @property
    def medium_priority_insights(self):
        """Get medium priority insights.
        
        :rtype: List of :class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceInsights`
        """
        return self.get_insights('medium')
    
    @property
    def low_priority_insights(self):
        """Get low priority insights.
        
        :rtype: List of :class:`passivetotal.analyzer.illuminate.asi.AttackSurfaceInsights`
        """
        return self.get_insights('low')
    
    @property
    def cves(self):
        """Get a list of CVEs associated with this attack surface.
        
        :rtype: List of :class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVE`
        """
        if getattr(self, '_cves', None) is not None:
            return self._cves
        return self.get_cves()

    @property
    def components(self):
        """List of components (detections) vulnerable to this CVE in this attack surface."""
        if getattr(self, '_components', None) is not None:
            return self._components
        return self.get_components()


class AttackSurfaceInsights(RecordList, ForPandas):

    """List of insights associated with an attack surface."""

    def __init__(self, attack_surface=None, level=None, api_response=None):
        self._attack_surface = attack_surface
        self._level = level
        if api_response is not None:
            self._parse(api_response)
    
    def _get_shallow_copy_fields(self):
        return ['_attack_surface','_level','_count_active_insights',
                '_count_total_insights','_count_total_observations']
    
    def _get_sortable_fields(self):
        return ['name','description','observation_count']
    
    def _get_dict_fields(self):
        return ['str:attack_surface','active_insight_count',
                'total_insight_count','total_observations']
    
    def _parse(self, api_response):
        self._count_active_insights = api_response.get('activeInsightCount')
        self._count_total_insights = api_response.get('totalInsightCount')
        self._count_total_observations = api_response.get('totalObservations')
        self._records = []
        for insight in api_response.get('insights',[]):
            self._records.append(
                AttackSurfaceInsight(self._attack_surface, self._level, insight)
            )
    
    @staticmethod
    def load(attack_surface, level):
        if attack_surface.is_own:
            response = get_api('Illuminate').get_asi_priority(level)
        else:
            response = get_api('Illuminate').get_asi_3p_vendor_priority(attack_surface.id, level)
        return AttackSurfaceInsights(attack_surface, level, response)
    
    @property
    def attack_surface(self):
        """Attach surface these insights are associated with.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurface`
        """
        return self._attack_surface
    
    @property
    def level(self):
        return self._level

    @property
    def active_insight_count(self):
        return self._count_active_insights
    
    @property
    def only_active_insights(self):
        """Filter to only active insights (insights with active observations).
        
        :rtype: bool
        """
        return self.filter(has_observations=True)
    
    @property
    def total_insight_count(self):
        return self._count_total_insights
    
    @property
    def total_observations(self):
        return self._count_total_observations
        



class AttackSurfaceInsight(Record, ForPandas):

    """An insight associated with an attack surface."""

    def __init__(self, attack_surface, level, api_response):
        self._attack_surface = attack_surface
        self._level = level
        self._parse(api_response)
    
    def __str__(self):
        return '{0.name}'.format(self)
    
    def _get_dict_fields(self):
        return ['id','name','level','description','observation_count','link']
    
    def _parse(self, api_response):
        self._name = api_response.get('name')
        self._description = api_response.get('description')
        self._count_observations = api_response.get('observationCount')
        self._link = api_response.get('link')
        if self._link is not None:
            url, querystring = self._link.split('?')
            self._insight_id = url.split('/')[-1]
            params = dict(parse_qsl(querystring))
            self._group_by = params.get('groupBy')
            self._segment_by = params.get('segmentBy')
    
    def to_dataframe(self):
        """Render this insight as a Pandas DataFrame.
        
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['name','level','description','observation_count']
        as_d = OrderedDict()
        as_d['insight_id'] = self.id
        as_d['asi_id'] = self.attack_surface.id
        for col in cols:
            as_d[col] = getattr(self, col)
        return pd.DataFrame.from_records([as_d])
    
    @property
    def id(self):
        """Unique ID for the insight."""
        return self._insight_id
    
    @property
    def level(self):
        """Priority level of this insight."""
        return self._level
    
    @property
    def attack_surface(self):
        """Attack surface this insight is associated with.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurface`
        """
        return self._attack_surface
    
    @property
    def name(self):
        """Insight short name."""
        return self._name
    
    @property
    def description(self):
        """Insight long description."""
        return self._description
    
    @property
    def link(self):
        """API link to get observations."""
        return self._link
    
    @property
    def observation_count(self):
        """Number of observations (assets) impacted by this insight."""
        return self._count_observations
    
    @property
    def has_observations(self):
        """Whether this insight has any active observations (assets)."""
        return self.observation_count > 0
    
    def get_observations(self, pagesize=INDICATOR_PAGE_SIZE):
        """Get a list of impacted assets (observations).
        
        :param pagesize: Size of pages to retrieve from the API.
        """
        self._observations = AttackSurfaceObservations(self, self._group_by, self._segment_by)
        self._observations.load_all_pages()
        return self._observations

    @property
    def observations(self):
        """List of impacted assets."""
        if getattr(self, '_observations', None) is not None:
            return self._observations
        return self.get_observations()



class AttackSurfaceObservations(RecordList, PagedRecordList, ForPandas):

    """List of observations (assets) associated with an attack surface insight."""

    def __init__(self, insight, group_by, segment_by, pagesize=400):
        self._totalrecords = None
        self._insight = insight
        self._group_by = group_by
        self._segment_by = segment_by
        self._records = []
        self._pagination_current_page = 0
        self._pagination_page_size = pagesize
        self._pagination_has_more = True
        if insight.attack_surface.is_own:
            self._pagination_callable = partial(
                get_api('Illuminate').get_asi_insights,
                insight.id,
                groupBy=group_by,
                segmentBy=segment_by
            )
        else:
            self._pagination_callable = partial(
                get_api('Illuminate').get_asi_3p_vendor_insights,
                insight.attack_surface.id,
                insight.id,
                groupBy=group_by,
                segmentBy=segment_by
            )
    
    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_pagination_current_page','_pagination_page_size',
                '_insight', '_pagination_callable', '_pagination_has_more']
    
    def _get_sortable_fields(self):
        return ['type','name','firstseen','lastseen']
    
    def _pagination_parse_page(self, api_response):
        """Parse a page of API response data."""
        self._totalrecords = api_response.get('totalCount')
        if self._pagination_current_page == 0:
            self._records = []
        for result in api_response.get('assets',[]):
            self._records.append(AttackSurfaceObservation(self._insight, result))
    
    @property
    def asset_types(self):
        """List of unique asset types in this observation list."""
        return list(set([ obs.type for obs in self]))
    
    @property
    def hostnames(self):
        """List of unique hostnames in this observation list.
        
        :rtype: :class:`passivetotal.analyzer.Hostname`
        """
        return list(set([ obs.hostname for obs in self if obs.type=='HOST']))
    
    @property
    def ips(self):
        """List of unique IP addresses in this observation list.
        
        :rtype: :class:`passivetotal.analyzer.IPAddress`
        """
        return list(set([ obs.ip for obs in self if obs.type=='IP_ADDRESS']))



class AttackSurfaceObservation(Record, FirstLastSeen, ForPandas):
    
    def __init__(self, insight, api_response):
        self._insight = insight
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._type = api_response.get('type')
        self._name = api_response.get('name')
    
    def __str__(self):
        return '{}'.format(self._name)
    
    def __repr__(self):
        return '<AttackSurfaceObservation {0.type}:{0.name}>'.format(self._type, self._name)
    
    def _get_dict_fields(self):
        return ['type','name','str:firstseen','str:lastseen']
    
    def to_dataframe(self):
        """Render this object as a Pandas dataframe.
        
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['type','name','firstseen','lastseen']
        as_d = {
            f: getattr(self, f) for f in cols
        }
        return pd.DataFrame.from_records([as_d], columns=cols)

    @property
    def type(self):
        return self._type
    
    @property
    def name(self):
        return self._name
    
    @property
    def insight(self):
        return self._insight
    
    @property
    def hostname(self):
        if self._type != 'HOST':
            return None
        try:
            return get_object(self._name, 'Hostname')
        except AnalyzerError:
            return None
    
    @property
    def ip(self):
        if self._type != 'IP_ADDRESS':
            return None
        try:
            return get_object(self._name, 'IPAddress')
        except AnalyzerError:
            return None