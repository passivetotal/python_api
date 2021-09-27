from datetime import datetime
from functools import partial, lru_cache


from passivetotal.analyzer import get_api
from passivetotal.analyzer._common import (
    Record, RecordList, PagedRecordList, FirstLastSeen, ForPandas, AnalyzerError
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
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurface`
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
    def article(self):
        """CVE article with complete details on this vulnerability.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.vuln.VulnArticle`
        """
        return VulnArticle.load(self._cve_id)
    
    @property
    def attack_surface(self):
        """Attack surface this CVE is associated with.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurface`
        """
        return self._attack_surface
    
    @property
    def description(self):
        """Description of the CVE, retrieved from the vulnerability article associated with this CVE."""
        return self.article.description
    
    @property
    def publish_date(self):
        """Publication date of the vulnerability article associated with this CVE."""
        return self.article.date_published
    
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
        """List of observations (assets) in this attack surface vulnerable to this CVE.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEObservations`
        """
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
        
        :rtype: :class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVE`
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
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurface`
        """
        return self.cve.attack_surface
    
    @property
    def cve(self):
        """CVE this observation is vulnerable to, in the context of a specific attack surface.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVE`
        """
        return self._cve
    
    @property
    def cve_id(self):
        """RiskIQ identifier for the CVE this observation is vulnerable to."""
        return self.cve.id
    
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
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurface`
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
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurface`
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



class VulnArticle(Record, ForPandas):

    """Vulnerabilty report providing details on impacted assets and third-party vendors."""

    _instances = {}

    def __new__(cls, id=None, api_response=None):
        if id is None and api_response is not None and 'cveInfo' in api_response and 'cveId' in api_response['cveInfo']:
            id = api_response['cveInfo'].get('cveId')
        if id is not None:
            self = cls._instances.get(id)
            if self is not None:
                return self
        self = cls._instances[id] = object.__new__(cls)
        self._is_loaded = False
        if api_response is not None:
            self._parse(api_response)
        return self
    
    def __repr__(self):
        return '<VulnArticle {}>'.format(self._id)
    
    def __str__(self):
        try:
            cwe_list = '({})'.format(','.join(self.cwes))
        except Exception:
            cwe_list = ''
        return '[{0.id}] {0.description}{1}'.format(self, cwe_list)
    
    def _parse(self, api_response):
        self._id = api_response['cveInfo']['cveId']
        self._description = api_response['cveInfo']['description']
        self._cwes = api_response['cveInfo']['cwes']
        self._priority_score = api_response['cveInfo']['priorityScore']
        self._cvss2_score = api_response['cveInfo']['cvss2Score']
        self._cvss3_score = api_response['cveInfo']['cvss3Score']
        self._date_published = api_response['cveInfo']['datePublished']
        self._date_created = api_response['cveInfo']['dateCreated']
        self._date_publisher_updated = api_response['cveInfo']['datePublisherUpdate']
        self._references = api_response['cveInfo']['references']
        self._components = api_response['components']
        self._impacted3p = api_response['impactedThirdParties']
        self._observation_count = api_response['observationCount']
        self._link = api_response['articlesLink']
        self._is_loaded = True
    
    def _api_get_article(self, id):
        response = get_api('Illuminate').get_vuln_article(id)
        self._parse(response)
    
    def _get_dict_fields(self):
        return ['id','description','cwes','score','cvss2score','cvss3score','str:date_published',
                'str:date_updated','str:date_publisher_updated','references','components',
                'observation_count']
    
    def to_dataframe(self, view='info'):
        """Render this object as a Pandas dataframe.

        :param view: View to generate (info, references, components, or impacts)
        
        :rtype: :class:`pandas.DataFrame`
        """
        views = ['info','references','components','impacts']
        if view not in views:
            raise AnalyzerError('view must be one of {}'.format(views))
        pd = self._get_pandas()
        cols = {
            'info': ['cve_id','description','score','cvss2score','cvss3score','date_published','date_created',
                     'date_pubupdate','observations','references','components','impacts'],
            'references': ['cve_id','reference_url','reference_name'],
            'components': ['cve_id','component'],
            'impacts': ['cve_id', 'vendor_name','vendor_id','observation_count']
        }
        records = {
            'info': [{
                'cve_id': self.id,
                'description': self.description,
                'score': self.score,
                'cvss2score': self.cvss2score,
                'cvss3score': self.cvss3score,
                'date_published': self.date_published,
                'date_created': self.date_created,
                'date_pubupdate': self.date_publisher_updated,
                'observations': self.observation_count,
                'references': len(self.references),
                'components': len(self.components),
                'impacts': len(self._impacted3p)
            }],
            'references': [{
                    'cve_id': self.id,
                    'reference_url': r['url'],
                    'reference_name': r['name']
                } for r in self.references ],
            'components': [{
                    'cve_id': self.id,
                    'component': c['name']
                } for c in self.components ],
            'impacts': [{
                    'cve_id': self.id,
                    'vendor_name': i.vendor_name,
                    'vendor_id': i.vendor_id,
                    'observation_count': i.observation_count  
                    } for i in self.attack_surfaces ]
        }
        return pd.DataFrame.from_records(records[view], index='cve_id', columns=cols[view])
    
    @staticmethod
    def load(id):
        """Load a Vulnerability Article by ID.
        
        :rtype: :class:`VulnArticle`
        """
        article = VulnArticle(id)
        if not article._is_loaded:
            article._api_get_article(id)
        return article
    
    @property
    def id(self):
        """CVE identifier string (alias for cve_id)."""
        return self._id
    
    @property
    def cve_id(self):
        """CVE identifier string."""
        return self._id
    
    @property
    def osint_articles(self):
        """Get a list of RiskIQ open-source intelligence articles that reference this vulnerability.
        
        :rtype: :class:`passivetotal.analyzer.articles.ArticlesList`
        """
        from passivetotal.analyzer.articles import ArticlesList
        return ArticlesList.find(self.id)
    
    @property
    def description(self):
        """Narrative description of the CVE."""
        return self._description
    
    @property
    def cwes(self):
        """List of CWE IDs."""
        return self._cwes
    
    @property
    def score(self):
        """RiskIQ-assigned priority score for this vulnerability, ranging between 0 and 100."""
        return self._priority_score
    
    @property
    def cvss2score(self):
        """The CVSS2 score for this vulnerability."""
        return self._cvss2_score
    
    @property
    def cvss3score(self):
        """The CVSSS3 score for this vulnerability."""
        return self._cvss3_score
    
    @property
    def date_published(self):
        """The date the article was published."""
        return datetime.fromisoformat(self._date_published)
    
    @property
    def date_published_raw(self):
        """The raw (string) value returned from the API with the date the article was published."""
        return self._date_published
    
    @property
    def date_created(self):
        """The date the article was created."""
        return datetime.fromisoformat(self._date_created)

    @property
    def date_created_raw(self):
        """The raw (string) value returned from the API with the date the article was created."""
        return self._date_created
    
    @property
    def date_publisher_updated(self):
        """The date the article was updated by the publisher."""
        return datetime.fromisoformat(self._date_publisher_updated)

    @property
    def date_publisherupdate_raw(self):
        """The raw (string) value returned from the API with the date the article was updated by the publisher."""
        return self._date_publisher_updated
    
    @property
    def references(self):
        """List of references for this article."""
        return self._references
    
    @property
    def components(self):
        """List of components (detections) RiskIQ will search for to determine if assets are impacted by this vulnerability."""
        return self._components
    
    @property
    @lru_cache(maxsize=None)
    def attack_surfaces(self):
        """List of Illuminate Attack Surfaces (aka third-party vendors) with assets impacted by this vulnerability.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.vuln.VulnArticleImpacts`
        """
        return VulnArticleImpacts(self, self._impacted3p)
    
    @property
    def observation_count(self):
        """Number of observations (assets) within the primary attack surface that are impacted by this vulnerability."""
        return self._observation_count
    
    @property
    def observations(self):
        """List of observations (assets) within the primary attack surface that are impacted by this vulnerability."""
        from . import AttackSurface
        attack_surface = AttackSurface.load()
        article = {
            'cveId': self.id,
            'cwes': self.cwes,
            'priorityScore': self.score,
            'observationCount': self.observation_count,
            'cveLink': ''
        }
        cve = AttackSurfaceCVE(attack_surface, article)
        return cve.observations



class VulnArticleImpacts(RecordList, ForPandas):

    """List of Illuminate Attack Surfaces impacted by a vulnerability."""

    def __init__(self, article=None, impacts=[]):
        self._records = []
        if article is not None:
            self._article = article
            if len(impacts):
                self._records = [ VulnArticleImpact(self._article, i) for i in impacts ]
    
    def __repr__(self):
        return '<VulnArticleImpacts {0.article.id}>'.format(self)
    
    def __str__(self):
        return '{0.article.id} impacts {0.impact_count:,} attack surfaces(s)'.format(self)

    def _get_dict_fields(self):
        return ['cve_id', 'impact_count']

    def _get_shallow_copy_fields(self):
        return ['_article']
    
    def _get_sortable_fields(self):
        return ['vendor_name','vendor_id','observation_count']
    
    @property
    def article(self):
        """Article that describes the vulnerability impacting these attack surfaces."""
        return self._article
    
    @property
    def attack_surfaces(self):
        """List of impacted attack surfaces.
        
        :rtypte: :class:`passivetotal.analyzer.illuminate.vuln.VulnArticleImpact`
        """
        return self._records
    
    @property
    def cve_id(self):
        """CVE identifier for the vulnerability this article applies to."""
        return self.article.id
    
    @property
    def impact_count(self):
        """Number of attack surfaces impacted by this vulnerability."""
        return len(self._records)
        
    

class VulnArticleImpact(Record, ForPandas):

    """An impacted third-party attack surface with observations (assets) affected by a given vulnerabilty."""

    def __init__(self, article, api_response=None):
        self._article = article
        if api_response is not None:
            self._parse(api_response)
        
    def __repr__(self):
        return "<VulnArticleImpact '{}'>".format(self._vendorname)
    
    def __str__(self):
        return '{0.vendor_name}: {0.observation_count:,} observations'.format(self)
    
    def _get_dict_fields(self):
        return ['vendor_name', 'vendor_id', 'observation_count']

    def _parse(self, api_response):
        self._vendorid = api_response['vendorID']
        self._vendorname = api_response['name']
        self._assetcount = api_response['assetCount']
    
    @property
    def article(self):
        """Article that describes the vulnerability this observation (asset) is impacted by.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.vuln.VulnArticle`
        """
        return self._article

    @property
    def vendor_name(self):
        """Name of the vendor with observations (assets) impacted by this vulnerability."""
        return self._vendorname
    
    @property
    def vendor_id(self):
        """The RiskIQ-assigned identifier for this vendor."""
        return self._vendorid
    
    @property
    def attack_surface(self):
        """Illuminate Attack Surface for the third-party vendor impacted by this vulnerability.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.asi.AttackSurface`
        """
        from . import AttackSurface
        return AttackSurface.load(self._vendorid)
    
    @property
    def observation_count(self):
        """Number of observations (assets) within a vendor's attack surface that are impacted by this vulnerability."""
        return self._assetcount
    
    @property
    def observations(self):
        """List of observations (assets) within this vendor's attack surface that are impacted by this vulnerability.
        
        :rtype: :class:`passivetotal.analyzer.illuminate.vuln.AttackSurfaceCVEObservations`
        """
        article = {
            'cveId': self.article.id,
            'cwes': self.article.cwes,
            'priorityScore': self.article.score,
            'observationCount': self.article.observation_count,
            'cveLink': ''
        }
        cve = AttackSurfaceCVE(self.attack_surface, article)
        return cve.observations


    

    
