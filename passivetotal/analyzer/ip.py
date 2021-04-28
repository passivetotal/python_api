"""IP Address analyzer for the RiskIQ PassiveTotal API."""


from passivetotal.analyzer import get_api, get_config
from passivetotal.analyzer._common import is_ip, AnalyzerError
from passivetotal.analyzer.pdns import PdnsResolutions
from passivetotal.analyzer.services import Services
from passivetotal.analyzer.ssl import Certificates
from passivetotal.analyzer.summary import IPSummary
from passivetotal.analyzer.hostpairs import HasHostpairs
from passivetotal.analyzer.cookies import HasCookies
from passivetotal.analyzer.trackers import HasTrackers
from passivetotal.analyzer.components import HasComponents
from passivetotal.analyzer.illuminate import HasReputation



class IPAddress(HasComponents, HasCookies, HasHostpairs, HasTrackers, HasReputation):

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
            self._resolutions = None
            self._services = None
            self._ssl_history = None
            self._summary = None
            self._whois = None
            self._components = None
            self._cookies = None
            self._trackers = None
            self._pairs = {}
            self._pairs['parents'] = None
            self._pairs['children'] = None
            self._reputation = None
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

    def _api_get_resolutions(self, unique=False, start_date=None, end_date=None, timeout=None, sources=None):
        """Query the pDNS API for resolution history."""
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
        """Query the services API for service and port history."""
        response = get_api('Services').get_services(query=self._ip)
        self._services = Services(response)
        return self._services

    def _api_get_ssl_history(self):
        """Query the SSL API for certificate history."""
        response = get_api('SSL').get_ssl_certificate_history(query=self._ip)
        self._ssl_history = Certificates(response)
        return self._ssl_history

    def _api_get_summary(self):
        """Query the Cards API for summary data."""
        response = get_api('Cards').get_summary(query=self._ip)
        self._summary = IPSummary(response)
        return self._summary

    def _api_get_whois(self):
        """Query the pDNS API for resolution history."""
        self._whois = get_api('Whois').get_whois_details(query=self._ip)
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
        if getattr(self, '_ssl_history'):
            return self._ssl_history
        return self._api_get_ssl_history()
    
    @property
    def resolutions(self):
        """:class:`passivetotal.analyzer.pdns.PdnsResolutions` where this 
        IP was the DNS response value.
            
        Bounded by dates set in :meth:`passivetotal.analyzer.set_date_range`.
        `timeout` and `sources` params are also set by the analyzer configuration.
        
        Provides list of :class:`passivetotal.analyzer.pdns.PdnsRecord` objects.
        """
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
        """Summary of PassiveTotal data available for this IP.
        
        :rtype: :class:`passivetotal.analyzer.summary.IPSummary`
        """
        if getattr(self, '_summary'):
            return self._summary
        return self._api_get_summary()
    
    @property
    def whois(self):
        """Whois record details for this IP."""
        if getattr(self, '_whois'):
            return self._whois
        return self._api_get_whois()