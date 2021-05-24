"""IP Address analyzer for the RiskIQ PassiveTotal API."""


from passivetotal.analyzer import get_api, get_config
from passivetotal.analyzer._common import is_ip, AnalyzerError
from passivetotal.analyzer.whois import IPWhois
from passivetotal.analyzer.pdns import HasResolutions
from passivetotal.analyzer.services import Services
from passivetotal.analyzer.ssl import Certificates
from passivetotal.analyzer.summary import IPSummary, HasSummary
from passivetotal.analyzer.hostpairs import HasHostpairs
from passivetotal.analyzer.cookies import HasCookies
from passivetotal.analyzer.trackers import HasTrackers
from passivetotal.analyzer.components import HasComponents
from passivetotal.analyzer.illuminate import HasReputation
from passivetotal.analyzer.articles import HasArticles
from passivetotal.analyzer.enrich import HasMalware
from passivetotal.analyzer.projects import IsArtifact



class IPAddress(HasComponents, HasCookies, HasHostpairs, HasTrackers, 
                HasReputation, HasArticles, HasResolutions, HasSummary,
                HasMalware, IsArtifact):

    """Represents an IPv4 address such as 8.8.8.8
    
    Instances are stored as class members so subsequent
    instantiations for the same IP return the same object.

    Because of this, storing instances in variables is optional, which
    can be especially useful in interactive sessions such as Jupyter notebooks.
    
    """
    _instances = {}

    def __new__(cls, ip):
        """Create or find an instance for the given IP."""
        if not is_ip(ip):
            raise AnalyzerError('Invalid IP address')
        self = cls._instances.get(ip)
        if self is None:
            self = cls._instances[ip] = object.__new__(IPAddress)
            self._ip = ip
            self._pairs = {}
            self._pairs['parents'] = None
            self._pairs['children'] = None
        return self

    def __str__(self):
        return self._ip
    
    def __repr__(self):
        return "IPAddress('{}')".format(self.ip)
    
    def reset(self, prop=None):
        """Reset this instance to clear all (default) or one cached properties.

        Useful when changing module-level settings such as analyzer.set_date_range().

        :param str prop: Property to reset (optional, if none provided all values will be cleared)
        """
        resettable_fields = ['whois','resolutions','summary','components',
                             'services','ssl_history',
                             'cookies','trackers','pairs','reputation']
        if not prop:
            for field in resettable_fields:
                setattr(self, '_'+field, None)
            self._reset_hostpairs()
        else:
            if prop not in resettable_fields:
                raise ValueError('Invalid property to reset')
            if prop == 'pairs':
                self._reset_hostpairs()
            else:
                setattr(self, '_'+prop, None)
    
    def get_host_identifier(self):
        """Alias for the IP address as a string.
        
        Used for API queries that accept either a hostname or an IP
        address as the query value.
        """
        return self._ip

    def _api_get_services(self):
        """Query the services API for service and port history."""
        response = get_api('Services').get_services(query=self._ip)
        self._services = Services(response)
        return self._services
    
    def _api_get_summary(self):
        """Query the Cards API for summary data."""
        response = get_api('Cards').get_summary(query=self.get_host_identifier())
        self._summary = IPSummary(response)
        return self._summary

    def _api_get_ssl_history(self):
        """Query the SSL API for certificate history."""
        response = get_api('SSL').get_ssl_certificate_history(query=self._ip)
        self._ssl_history = Certificates(response)
        return self._ssl_history

    def _api_get_whois(self):
        """Query the pDNS API for resolution history."""
        response = get_api('Whois').get_whois_details(query=self._ip)
        self._whois = IPWhois(response)
        return self._whois
    
    @property
    def ip(self):
        """IP address as a string."""
        return self._ip
    
    @property
    def certificates(self):
        """History of :class:`passivetotal.analyzer.ssl.Certificates` 
        presented by services hosted on this IP address.
        """
        if getattr(self, '_ssl_history', None) is not None:
            return self._ssl_history
        return self._api_get_ssl_history()
    
    @property
    def services(self):
        if getattr(self, '_services', None) is not None:
            return self._services
        return self._api_get_services()
    
    
    @property
    def whois(self):
        """Most recently available Whois record for IP.

        :rtype: :class:`passivetotal.analyzer.whois.IPWhois`
        """
        if getattr(self, '_whois', None) is not None:
            return self._whois
        return self._api_get_whois()