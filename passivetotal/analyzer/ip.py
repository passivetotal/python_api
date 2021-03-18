from passivetotal.analyzer import get_api, get_config
from passivetotal.analyzer.pdns import PdnsResolutions
from passivetotal.analyzer.services import Services
from passivetotal.analyzer.ssl import Certificates
from passivetotal.analyzer.summary import IPSummary



class IPAddress(object):
    _instances = {}

    def __new__(cls, ip):
        self = cls._instances.get(ip)
        if self is None:
            self = cls._instances[ip] = object.__new__(IPAddress)
            self._ip = ip
            self._resolutions = None
            self._services = None
            self._ssl_history = None
            self._summary = None
            self._whois = None
        return self

    def __str__(self):
        return self._ip
    
    def __repr__(self):
        return "IPAddress('{}')".format(self.ip)
    
    def _api_get_resolutions(self, unique=False, start_date=None, end_date=None, timeout=None, sources=None):
        meth = get_api('DNS').get_unique_resolutions if unique else get_api('DNS').get_passive_dns
        response = meth(
            query=self._ip,
            start=start_date,
            end=end_date,
            timeout=timeout,
            sources=sources
        )
        self._resolutions = PdnsResolutions(api_response=response)
        return self._resolutions
    
    def _api_get_services(self):
        response = get_api('Services').get_services(query=self._ip)
        self._services = Services(response)
        return self._services

    def _api_get_ssl_history(self):
        response = get_api('SSL').get_ssl_certificate_history(query=self._ip)
        self._ssl_history = Certificates(response)
        return self._ssl_history

    def _api_get_summary(self):
        response = get_api('Cards').get_summary(query=self._ip)
        self._summary = IPSummary(response)
        return self._summary

    def _api_get_whois(self):
        self._whois = get_api('Whois').get_whois_details(query=self._ip)
        return self._whois
    
    @property
    def ip(self):
        return self._ip
    
    @property
    def certificates(self):
        if getattr(self, '_ssl_history'):
            return self._ssl_history
        return self._api_get_ssl_history()
    
    @property
    def resolutions(self):
        if getattr(self, '_resolutions'):
            return self._resolutions
        config = get_config()
        return self._api_get_resolutions(
            unique=False, 
            start_date=config['start_date'],
            end_date=config['end_date'],
            timeout=config['pdns_timeout'],
            sources=config['pdns_sources']
        )
    
    @property
    def services(self):
        if getattr(self, '_services'):
            return self._services
        return self._api_get_services()

    @property
    def summary(self):
        if getattr(self, '_summary'):
            return self._summary
        return self._api_get_summary()
    
    @property
    def whois(self):
        if getattr(self, '_whois'):
            return self._whois
        return self._api_get_whois(compact=False)