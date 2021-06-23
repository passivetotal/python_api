from collections import OrderedDict, namedtuple
from functools import lru_cache, total_ordering, partial
from passivetotal.analyzer import get_api
from passivetotal.analyzer._common import (
    AsDictionary, ForPandas, RecordList, Record, FirstLastSeen, 
    PagedRecordList, AnalyzerAPIError
)


INDICATOR_PAGE_SIZE = 200


@total_ordering
class ReputationScore(AsDictionary, ForPandas):

    """RiskIQ Illuminate Reputation profile for a hostname or an IP."""

    def __init__(self, api_response, query=None):
        self._response = api_response
        self._query = query
    
    def __str__(self):
        return '{0.score} ({0.classification})'.format(self)
    
    def __repr__(self):
        return '<ReputationScore {0.score} "{0.classification}">'.format(self)
    
    def __int__(self):
        return self.score
    
    def __gt__(self, other):
        return self.score > other
    
    def __eq__(self, other):
        return self.score == other
    
    def to_dataframe(self, explode_rules=False, drop_links=False):
        """Render this object as a Pandas DataFrame.

        :param explode_rules: Whether to create a row for each rule using `pandas.DataFrame.explode` (optional, defaults to False)
        :param drop_links: Whether to include links when present in exploded rules (optional, defaults to False)
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        as_d = OrderedDict(
            query       = self._query,
            score       = self.score,
            classification = self.classification,
            rules = self.rules
        )
        df = pd.DataFrame([as_d])
        if not explode_rules:
            return df
        df_rules = df.explode('rules', ignore_index=True)
        df_wide = pd.concat([df_rules.drop('rules', axis='columns'), df_rules['rules'].apply(pd.Series)], axis='columns')
        if drop_links:
            return df_wide.drop('link', axis='columns')
        return df_wide


    @property
    def as_dict(self):
        """Representation as a dictionary object."""
        return {
            'score': self.score,
            'classification': self.classification,
            'rules': self.rules,
        }

    @property
    def score(self):
        """Reputation score as an integer ranging from 0-100.

        Higher values indicate a greater likelihood of maliciousness.
        """
        return self._response.get('score')
    
    @property
    def classification(self):
        """Reputation classification as a string. 

        Typical values include GOOD, SUSPICIOUS, MALICIOUS, or UNKNOWN.
        """
        return self._response.get('classification')
    
    @property
    def rules(self):
        """List of rules that informed the reputation score.

        Returns a list of dictionaries.
        """
        return self._response.get('rules')



class HasReputation:

    """An object with a RiskIQ Illuminate Reputation score."""

    def _api_get_reputation(self):
        """Query the reputation endpoint."""
        query=self.get_host_identifier()
        response = get_api('Illuminate').get_reputation(query=query)
        self._reputation = ReputationScore(response, query)
        return self._reputation

    @property
    def reputation(self):
        """RiskIQ Illuminate Reputation profile for a hostname or IP.

        :rtype: :class:`passivetotal.analyzer.illuminate.ReputationScore`
        """
        if getattr(self, '_reputation', None) is not None:
            return self._reputation
        return self._api_get_reputation()



class IntelProfiles(RecordList, ForPandas):

    """List of RiskIQ Intel Profiles from the Illuminate CTI module."""
    
    def __getitem__(self, key):
        if isinstance(key, str):
            filtered = self.filter(id=key)
            if len(filtered) != 1:
                raise KeyError('No profile found for id {}'.format(key))
            return filtered[0]
        return super().__getitem__(key)

    def _get_shallow_copy_fields(self):
        return ['_totalrecords']
    
    def _get_sortable_fields(self):
        return ['id','title']
    
    def _get_dict_fields(self):
        return ['totalrecords']

    @staticmethod
    def load(query=None, profile_type=None):
        """Get a list of all RiskIQ Intel Profiles.

        :param query: Submit a query param to the API to limit results to only matching providers (optional)
        :param profile_type: Submit a type param to the API to limit results to only certain profile types (optional)
        """
        response = get_api('Illuminate').get_intel_profiles(query=query, type=profile_type)
        return IntelProfiles(response)
    
    @staticmethod
    def find_by_indicator(query, **kwargs):
        """Search profiles by indicator.

        :param query: Indicator value as a string
        :param types: Types of indicators (optional)
        :param categories: Categories of indicators (optional)
        :param sources: Sources of indicators [riskiq, osint] (optional)
        """
        try:
            response = get_api('Illuminate').get_intel_profiles_for_indicator(query, **kwargs)
        except AnalyzerAPIError as e:
            if e.status_code == 404:
                return IntelProfiles()
            else:
                raise e
        return IntelProfiles(response)

    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalCount', 0)
        self._records = []
        for result in api_response.get('results', []):
            self._records.append(IntelProfile(id=result.get('id'),api_response=result))
    
    def to_dataframe(self, ignore_index=False, **kwargs):
        """Render this object as a Pandas dataframe."""
        pd = self._get_pandas()
        return pd.concat([ r.to_dataframe(**kwargs) for r in self], ignore_index=ignore_index)
    
    @property
    def totalrecords(self):
        """Total number of profiles available in this record list."""
        return self._totalrecords



class IntelProfile(Record, ForPandas):

    """RiskIQ Intel Profile on a specific actor group."""

    _instances = {}

    ProfileTag = namedtuple('ProfileTag','label,country')

    def __new__(cls, id=None, api_response=None):
        if id is not None:
            self = cls._instances.get(id)
            if self is not None:
                return self
            self = cls._instances[id] = object.__new__(cls)
            self._id = id
        self._has_details = False
        if api_response is not None:
            self._parse(api_response)
        return self
    
    def __str__(self):
        return self.title
    
    def __repr__(self):
        return '<IntelProfile "{0}">'.format(self.id)

    def _ensure_details(self):
        """Ensure details are loaded from the API for this profile."""
        if not getattr(self, '_has_details', False):
            response = get_api('Illuminate').get_intel_profile_details(self._id)
            self._parse(response)
    
    def _get_dict_fields(self):
        return ['id','title','indicatorcount_osint','indicatorcount_riskiq',
                'tags_raw','title']

    def _parse(self, api_response):
        """Parse an API response into object properties."""
        self._id = api_response.get('id')
        self._title = api_response.get('title')
        self._link = api_response.get('link')
        self._ioccount_osint = api_response.get('osintIndicatorsCount')
        self._ioccount_riskiq = api_response.get('riskIqIndicatorsCount')
        self._api_link_indicators = api_response.get('indicators')
        self._aliases = api_response.get('aliases')
        self._tags = api_response.get('tags')
        self._has_details = True
    
    @lru_cache(maxsize=None)
    def get_indicators(self, all_pages=True, types=None, categories=None, sources=None, pagesize=INDICATOR_PAGE_SIZE):
        """Get a list of indicators associated with this intel profile.

        Loads all pages of indicators by default. Results with identical params are cached.

        :param all_pages: Whether to retrieve all pages (optional, defaults to True)
        :param types: Types of indicators to search for (optional).
        :param categories: Categories of indicators to filter on (optional).
        :param sources: Sources of indicators [osint, riskiq] (optional).
        :param pagesize: Size of pages to return from the API (defaults to `INDICATOR_PAGE_SIZE`).
        """
        iocs = IntelProfileIndicatorList(
            profile_id=self._id,
            types=types,
            categories=categories,
            sources=sources,
            pagesize=pagesize
        )
        iocs.load_all_pages()
        return iocs

    def to_dataframe(self):
        """Render this profile as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['id','title','indicatorcount_osint','indicatorcount_riskiq','aliases','tags']
        as_d = {
            f: getattr(self, f) for f in cols
        }
        return pd.DataFrame.from_records([as_d], index='id', columns=cols)
    
    @property
    def aliases(self):
        """List of alternative names for this actor group."""
        self._ensure_details()
        return self._aliases
    
    @property
    def id(self):
        """RiskIQ identifier for this actor group."""
        return self._id
    
    @property
    def indicatorcount_osint(self):
        """Count of available indicators from open source intelligence reports."""
        self._ensure_details()
        return self._ioccount_osint
    
    @property
    def indicatorcount_riskiq(self):
        """Count of available indicators sourced from RiskIQ primary research."""
        self._ensure_details()
        return self._ioccount_riskiq
    
    @property
    def indicators(self):
        """Unfiltered indicator list associated with this intel profile.

        Calls `passivetotal.analyzer.illuminate.IntelProfile.get_indicators()'
        with default parameters. Use that method directly for more granular control.

        :rtype: :class:`passivetotal.analyzer.illuminate.IntelProfileIndicatorList`
        """
        return self.get_indicators()
    
    @property
    def tags(self):
        """List of profile tags associated with this actor group.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.IntelProfile.ProfileTag`
        """
        self._ensure_details()
        return [ self.ProfileTag(t['label'], t['countryCode']) for t in self._tags ]
    
    @property
    def tags_raw(self):
        """List of profile tags as returned by the API."""
        self._ensure_details()
        return self._tags
    
    @property
    def title(self):
        """RiskIQ title for this actor profile."""
        self._ensure_details()
        return self._title



class IntelProfileIndicatorList(RecordList, PagedRecordList, ForPandas):

    def __init__(self, profile_id=None, query=None, types=None, categories=None, sources=None, pagesize=INDICATOR_PAGE_SIZE):
        """List of indicators associated with a RiskIQ Intel Profile.
        
        :param profile_id: Threat intel profile ID to search for.
        :param query: Indicator value to query for.
        :param types: Types of indicators to search for (optional).
        :param categories: Categories of indicators to filter on (optional).
        :param sources: Sources of indicators [osint, riskiq] (optiona).
        """
        self._totalrecords = None
        self._types = []
        self._pagination_current_page = 0
        self._pagination_page_size = pagesize
        self._pagination_has_more = True
        self._records = []
        self._profile_id = profile_id
        self._pagination_callable = partial(
            get_api('Illuminate').get_intel_profile_indicators,
            self._profile_id,
            query=query,
            types=types,
            categories=categories,
            sources=sources,
            size=pagesize
        )
    
    def _get_shallow_copy_fields(self):
        return ['_totalrecords','_pagination_current_page','_pagination_page_size',
                '_types', '_pagination_callable', '_pagination_has_more', '_profile_id']
    
    def _get_sortable_fields(self):
        return ['id','firstseen','lastseen','type','category','value','is_osint','profile_id']

    def _pagination_parse_page(self, api_response):
        """Parse a page of API response data."""
        self._totalrecords = api_response.get('totalCount')
        self._types = api_response.get('types')
        if self._pagination_current_page == 0:
            self._records = []
        for result in api_response.get('results',[]):
            self._records.append(IntelProfileIndicator(result))
    
    def to_dataframe(self, ignore_index=False, **kwargs):
        """Render this object as a Pandas dataframe."""
        pd = self._get_pandas()
        return pd.concat([ r.to_dataframe(**kwargs) for r in self], ignore_index=ignore_index)
    
    @property
    def only_osint(self):
        """Filtered list with only indicators from open sources.

        :rtype: :class:`passivetotal.analyzer.illuminate.IntelProfileIndicatorList`
        """
        return self.filter(is_osint=True)
    
    @property
    def only_riskiq(self):
        """Filtered list with only indicators sourced by RiskIQ.

        :rtype: :class:`passivetotal.analyzer.illuminate.IntelProfileIndicatorList`
        """
        return self.filter(is_osint=False)

    @property
    def types(self):
        """List of indicator types in the list."""
        return self._types

    @property
    def values(self):
        """List of all values in the indicator list."""
        return [ i.value for i in self ]



class IntelProfileIndicator(Record, FirstLastSeen, ForPandas):

    """An indicator associated with an intel profile."""

    def __init__(self, api_response):
        self._id = api_response.get('id')
        self._firstseen = api_response.get('firstSeen')
        self._lastseen = api_response.get('lastSeen')
        self._profile_id = api_response.get('profileId')
        self._type = api_response.get('type')
        self._value = api_response.get('value')
        self._category = api_response.get('category')
        self._osint = api_response.get('osint')
        self._link = api_response.get('osintUrl')
        self._articleguids = api_response.get('articleGuids')
    
    def __repr__(self):
        return '<IntelProfileIndicator "{}">'.format(self._id)
    
    def __str__(self):
        return self._value
    
    def _get_dict_fields(self):
        return ['id','str:firstseen','str:lastseen','profile_id','type',
                'value','category','is_osint','osint_link','articleguids']
    
    def to_dataframe(self):
        """Render this object as a Pandas DataFrame.

        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        cols = ['id','value','type','category','firstseen','lastseen',
                'profile_id','is_osint','osint_link','articleguids']
        as_d = {
            f: getattr(self, f) for f in cols
        }
        df = pd.DataFrame.from_records([as_d], index='id', columns=cols)
        return df
    
    @property
    def id(self):
        """RiskIQ identifier for this indicator."""
        return self._id
    
    @property
    def profile_id(self):
        """RiskIQ identifier for the intel profile associated with this indicator."""
        return self._profile_id
    
    @property
    def intel_profile(self):
        """RiskIQ threat intel profile associated with this indicator.

        :rtype: :class:`passivetotal.analyzer.illuminate.IntelProfile`
        """
        return IntelProfile(id=self._profile_id)
    
    @property
    def type(self):
        """Type of indicator."""
        return self._type
    
    @property
    def value(self):
        """Value of the indicator."""
        return self._value
    
    @property
    def category(self):
        """Indicator category."""
        return self._category
    
    @property
    def is_osint(self):
        """Whether this indicator was published in open source intelligence articles."""
        return self._osint
    
    @property
    def osint_link(self):
        """URL for the OSINT source of the indicator, or none if this is not an OSINT indicator."""
        return self._link
    
    @property
    def articleguids(self):
        """List of RiskIQ OSINT article GUIDs associated with this indicator."""
        return self._articleguids



class HasIntelProfiles:
    
    """An object that may be listed in threat intel profiles."""

    @property
    def intel_profiles(self):
        """List of RiskIQ Threat Intel Profiles that reference this host.

        For more granular searches, call the 
        `passivetotal.analyzer.illuminate.IntelProfiles.find_by_indicators()` method directly.

        :rtype: :class:`passivetotal.analyzer.illuminate.IntelProfiles`
        """
        if getattr(self, '_intel_profiles', None) is not None:
            return self._intel_profiles
        self._intel_profiles = IntelProfiles.find_by_indicator(self.get_host_identifier())
        return self._intel_profiles




