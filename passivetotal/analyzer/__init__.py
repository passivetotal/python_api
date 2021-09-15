"""Analyzer package for the RiskIQ PassiveTotal API."""

from collections import namedtuple
from datetime import datetime, timezone, timedelta
from passivetotal import *
from passivetotal._version import VERSION
from passivetotal.api import Context
from passivetotal.analyzer._common import AnalyzerError, AnalyzerAPIError, is_ip

DEFAULT_DAYS_BACK = 90

api_clients = {}
config = {
    'start_date': None,
    'end_date': None,
    'pdns_timeout': None,
    'pdns_sources': None,
    'is_ready': False,
    'pprint': { 'indent': 2 },
    'datesort': None,
    'dateorder': None,
    'project_name': None,
    'project_visiblity': 'analyzer',
    'project_guid': None
}


def init(**kwargs):
    """Instantiate API clients.

    Arguments are passed to the request wrapper constructors; if
    none are provided, the class method from_config()
    is called to instantiate an API client from config files.
    """
    api_classes = [
        (AccountClient,'Account'), 
        (ActionsClient, 'Actions'),
        (ArticlesRequest, 'Articles'),
        (AttributeRequest, 'Attributes'), 
        (CardsRequest, 'Cards'),
        (CookiesRequest, 'Cookies'),
        (DnsRequest, 'DNS'), 
        (EnrichmentRequest, 'Enrichment'), 
        (HostAttributeRequest, 'HostAttributes'),
        (IntelligenceRequest, 'Intelligence'), 
        (ProjectsRequest, 'Projects'), 
        (ServicesRequest, 'Services'),
        (SslRequest, 'SSL'), 
        (WhoisRequest, 'Whois'),
        (IlluminateRequest, 'Illuminate'),
        (ArticlesRequest, 'Articles'),
        (ProjectsRequest, 'Projects'),
        (ArtifactsRequest, 'Artifacts'),
        (MonitorRequest, 'Monitor'),
    ]
    for c, name in api_classes:
        if 'username' in kwargs and 'api_key' in kwargs:
            api_clients[name] = c(**kwargs)
        else:
            api_clients[name] = c.from_config(**kwargs)
        api_clients[name].exception_class = AnalyzerAPIError
        api_clients[name].set_context('python','passivetotal',VERSION,'analyzer')
    config['is_ready'] = True

def get_api(name):
    """Return an instance of an API client by name."""
    if not config['is_ready']:
        raise Exception('Analyzer is not initialized; run init() on the module to get started')
    try:
        return api_clients[name]
    except KeyError:
        raise Exception('Unknown API, must be one of {}'.format(','.join(api_clients.keys())))

def get_config(key=None):
    """Get the active configuration for the analyzer module."""
    if not config['start_date'] or not config['end_date']:
        set_date_range()
    if key:
        return config[key]
    return config

def get_object(input, type=None):
    """Get an Analyzer object for a given input and type. If no type is specified,
    type will be autodetected based on the input.

    If the input is already an Analyzer object it will be returned as-is.

    Returns :class:`analyzer.Hostname` or :class:`analyzer.IPAddress`.
    """
    if isinstance(input, IPAddress) or isinstance(input, Hostname):
        return input
    objs = {
        'IPAddress': IPAddress,
        'Hostname': Hostname
    }
    if type is None:
        type = 'IPAddress' if is_ip(input) else 'Hostname'
    elif type not in objs.keys():
        raise AnalyzerError('type must be IPAddress or Hostname')
    return objs[type](input) 

def get_version():
    """Get the current version of this package."""
    return VERSION

def set_context(provider, variant, version, feature=''):
    """Define the application context for an implementation using the analyzer module.

    Sets a header to be sent in API requests that is used for metrics and troubleshooting.
    
    :param provider: The company, partner, provider or other top-level application context.
    :param variant: The specific app, libary subcomponent, or feature category.
    :param version: Version of the app, feature or code setting the context.
    :param feature: Optional sub-feature, dashboard or script name.
    """
    for client in api_clients.values():
        client.set_context(provider, variant, version, feature)

def set_date_range(days_back=DEFAULT_DAYS_BACK, start=None, start_date=None, end=None, end_date=None):
    """Set a range of dates for all date-bounded API queries.

    By default, queries will be bounded by `analyzer.DEFAULT_DAYS_BACK`. Set `days_back` to 
    calculate the starting and ending dates automatically relative to today's date.

    Or, set the `start` and `end` params explicitly using a string in YYYY-MM-DD 00:00:00
    format or `start_date` and `end_date` params as datetime objects. 
    
    :param days_back: Number of days back to query (optional, defaults to DEFAULT_DAYS_BACK).
    :param start: Starting date as string in YYYY-MM-DD 00:00:00 format (optional).
    :param start_date: Starting date as datetime object (optional).
    :param end: Ending date as string in YYYY-MM-DD 00:00:00 format (optional).
    :param end_date: Ending date as datetime object (optional).
    """
    if start_date and end_date:
        start = start_date.strftime('%Y-%m-%d %H:%m:%S')
        end = end_date.strftime('%Y-%m-%d %H:%m:%S')
    if start and end:
        config['start_date'] = start
        config['end_date'] = end
    else:
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=days_back)
        config['start_date'] = past.date().isoformat() + ' 00:00:00'
        config['end_date'] = now.date().isoformat() + ' 00:00:00'

def set_pdns_timeout(timeout):
    """Set a timeout on pDNS queries to third-party sources."""
    config['pdns_timeout'] = timeout

def set_pdns_sources(sources):
    """Set a list of third-sources for pDNS queries."""
    config['pdns_sources'] = sources

def set_pprint_params(**kwargs):
    """Configure options for the Python prettyprint module."""
    config['pprint'] = kwargs

def set_datesort_lastseen():
    """Set the sort param for date-aware searches to 'lastSeen'.

    Especially relevant when searching crawl data such as components,
    cookies, hostpairs, and trackers.
    """
    config['datesort'] = 'lastSeen'

def set_datesort_firstseen():
    """Set the sort param for date-aware searches to 'firstSeen'.

    Especially relevant when searching crawl data such as components,
    cookies, hostpairs, and trackers.
    """
    config['datesort'] = 'firstSeen'

def clear_datesort():
    """Unset the sort and order param for date-aware searches to restore default behavior."""
    config['datesort'] = None
    config['dateorder'] = None

def set_datesort_ascending():
    """Set the order param for date-aware searches to 'asc'.

    Especially relevant when searching crawl data such as components,
    cookies, hostpairs, and trackers.
    """
    config['dateorder'] = 'asc'

def set_dateorder_descending():
    """Set the order param for date-aware searches to 'firstSeen'.

    Especially relevant when searching crawl data such as components,
    cookies, hostpairs, and trackers.
    """
    config['dateorder'] = 'desc'

def get_project():
    """Get the active project.
    
    :rtype: :class:`passivetotal.analyzer.projects.Project` 
    """
    if config['project_guid'] is None:
        return None
    return Project.find(config['project_guid'])

def set_project(name_or_guid, visibility='analyst', description='', tags=None, create_if_missing=True):
    """Set the active Illuminate Project for this investigation. 

    Used by Analyzer objects to persist results to projects. Performs an API query to determine if project
    exists, create it if it is missing, and obtain necessary details.

    :param name_or_guid: Project name or project GUID.
    :param visibility: Who can see the project: public, private or analyst (optional, defaults to 'analyst').
    :param description: Description of the project (optional).
    :param tags: List of tags to apply to the project (optional).
    :param create_if_missing: Whether to auto-create the project if it doesn't exist (optional, defaults to true)."""
    projreq = get_api('Projects')
    projects = projreq.find_projects(name_or_guid, visibility)
    if len(projects) == 0:
        if projreq.is_guid(name_or_guid):
            raise AnalyzerError('No project found with that GUID')
        if create_if_missing:
            result = projreq.create_project(name_or_guid, visibility, description=description, tags=tags)
            config['project_name'] = name_or_guid
            config['project_guid'] = result['guid']
            config['project_visibility'] = visibility
        else:
            raise AnalyzerError('Project does not exist and create_if_missing is False.')
    elif len(projects) == 1:
        config['project_name'] = projects[0]['name']
        config['project_guid'] = projects[0]['guid']
        config['project_visibility'] = projects[0]['visibility']
    else:
        raise AnalyzerError('More than one project found; narrow the search criteria or use a unique name')

def AttackSurface(id_or_name=None):
    """Find one attack surface.
        
    Call with no parameters to find your Attack Surface.
    Pass a number to load a specific Attack Surface by ID, or pass a string to load the entire
    list of Attack Surfaces and search them by case-insensitive substring.
    
    Raises `AnalyzerError` if no attack surfaces are found or if more than one Attack Surface name
    matches the parameter.
    
    :returns: :class:`passivetotal.illuminate.AttackSurface`
    """
    from passivetotal.analyzer.illuminate import AttackSurface as ASI
    return ASI.find(id_or_name)



from passivetotal.analyzer.hostname import Hostname
from passivetotal.analyzer.ip import IPAddress
from passivetotal.analyzer.ssl import CertificateField
from passivetotal.analyzer.articles import AllArticles
from passivetotal.analyzer.projects import Project, ProjectList
from passivetotal.analyzer.trackers import Tracker