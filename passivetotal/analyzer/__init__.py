from collections import namedtuple
from datetime import datetime, timezone, timedelta
from passivetotal import *

DEFAULT_DAYS_BACK = 30

api_clients = {}
config = {
    'start_date': None,
    'end_date': None,
    'pdns_timeout': None,
    'pdns_sources': None,
    'is_ready': False,
    'pprint': { 'indent': 2 },
}


def init(**kwargs):
    """Instantiate API clients.

    Arguments are passed to the client object constructors unless
    none are provided, in which case the class method from_config()
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
        (WhoisRequest, 'Whois')
    ]
    for c, name in api_classes:
        if 'username' in kwargs and 'api_key' in kwargs:
            api_clients[name] = c(**kwargs)
        else:
            api_clients[name] = c.from_config()
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
    if not config['start_date'] or not config['end_date']:
        set_date_range()
    if key:
        return config[key]
    return config

def set_date_range(days_back=DEFAULT_DAYS_BACK, start=None, end=None):
    if start and end:
        config['start_date'] = start
        config['end_date'] = end
    else:
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=days_back)
        config['start_date'] = past.date().isoformat() + ' 00:00:00'
        config['end_date'] = now.date().isoformat() + ' 00:00:00'

def set_pdns_timeout(timeout):
    config['pdns_timeout'] = timeout

def set_pdns_sources(sources):
    config['pdns_sources'] = sources

def set_pprint_params(**kwargs):
    config['pprint'] = kwargs

from passivetotal.analyzer.hostname import Hostname
from passivetotal.analyzer.ip import IPAddress
from passivetotal.analyzer.ssl import CertificateField