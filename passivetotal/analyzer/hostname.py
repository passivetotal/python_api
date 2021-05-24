"""Hostname analyzer for the RiskIQ PassiveTotal API."""

import socket
import tldextract
from passivetotal.analyzer import get_api, get_config, get_object
from passivetotal.analyzer._common import is_ip, refang, AnalyzerError
from passivetotal.analyzer.pdns import HasResolutions
from passivetotal.analyzer.summary import HostnameSummary, HasSummary
from passivetotal.analyzer.whois import DomainWhois
from passivetotal.analyzer.ssl import CertificateField
from passivetotal.analyzer.hostpairs import HasHostpairs
from passivetotal.analyzer.cookies import HasCookies
from passivetotal.analyzer.trackers import HasTrackers
from passivetotal.analyzer.components import HasComponents
from passivetotal.analyzer.illuminate import HasReputation
from passivetotal.analyzer.articles import HasArticles
from passivetotal.analyzer.enrich import HasMalware
from passivetotal.analyzer.projects import IsArtifact



class Hostname(HasComponents, HasCookies, HasTrackers, HasHostpairs, 
               HasReputation, HasArticles, HasResolutions, HasSummary,
               HasMalware, IsArtifact):

    """Represents a hostname such as api.passivetotal.org.
    
    Instances are stored as class members so subsequent
    instantiations for the same hostname return the same object.

    Because of this, storing instances in variables is optional, which
    can be especially useful in interactive sessions such as Jupyter notebooks.
    
    """

    _instances = {}

    def __new__(cls, hostname):
        """Create or find an instance for the given hostname."""
        hostname = refang(hostname)
        if is_ip(hostname):
            raise AnalyzerError('Use analyzer.IPAddress for IPv4 addresses.')
        self = cls._instances.get(hostname)
        if self is None:
            self = cls._instances[hostname] = object.__new__(Hostname)
            self._hostname = hostname
            self._pairs = {}
            self._pairs['parents'] = None
            self._pairs['children'] = None
        return self
    
    def __str__(self):
        return self._hostname
    
    def __repr__(self):
        return "Hostname('{}')".format(self.hostname)
    
    def reset(self, prop=None):
        """Reset this instance to clear all (default) or one cached properties.

        Useful when changing module-level settings such as analyzer.set_date_range().

        :param str prop: Property to reset (optional, if none provided all values will be cleared)
        """
        resettable_fields = ['whois','resolutions','summary','components',
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
        """Alias for the hostname as a string.
        
        Used for API queries that accept either a hostname or an IP
        address as the query value.
        """
        return self._hostname
    
    def _api_get_summary(self):
        """Query the Cards API for summary data."""
        response = get_api('Cards').get_summary(query=self.get_host_identifier())
        self._summary = HostnameSummary(response)
        return self._summary
    
    def _api_get_whois(self, compact=False):
        """Query the Whois API for complete whois details."""
        response = get_api('Whois').get_whois_details(query=self._hostname, compact_record=compact)
        self._whois = DomainWhois(response)
        return self._whois
    
    def _query_dns(self):
        """Perform a DNS lookup."""
        ip = socket.gethostbyname(self._hostname)
        self._current_ip = get_object(ip,'IPAddress')
        return self._current_ip
    
    def _extract(self):
        """Use the tldextract library to extract parts out of the hostname."""
        self._tldextract = tldextract.extract(self._hostname)
        return self._tldextract
    
    @property
    def domain(self):
        """Returns only the domain portion of the registered domain name for this hostname.

        Uses the `tldextract` library and returns the domain property of the 
        `ExtractResults` named tuple.
        """
        if getattr(self, '_tldextract', None) is not None:
            return self._tldextract.domain
        return self._extract().domain
    
    @property
    def tld(self):
        """Returns the top-level domain name (TLD) for this hostname.

        Uses the `tldextract` library and returns the suffix property of the 
        `ExtractResults` named tuple.
        """
        if getattr(self, '_tldextract', None) is not None:
            return self._tldextract.suffix
        return self._extract().suffix
    
    @property
    def registered_domain(self):
        """Returns the registered domain name (with TLD) for this hostname.

        Uses the `tldextract` library and returns the registered_domain property of the 
        `ExtractResults` named tuple.
        """
        if getattr(self, '_tldextract', None) is not None:
            return self._tldextract.registered_domain
        return self._extract().registered_domain
    
    @property
    def subdomain(self):
        """Entire set of subdomains for this hostname (third level and higher).

        Uses the `tldextract` library and returns the subdomain property of the 
        `ExtractResults` named tuple.
        """
        if getattr(self, '_tldextract', None) is not None:
            return self._tldextract.subdomain
        return self._extract().subdomain
    
    @property
    def hostname(self):
        """Hostname as a string."""
        return self._hostname
    
    @property
    def ip(self):
        """Hostname's current IP address.
        
        Performs an local on-demand DNS query if needed.

        :rtype: :class:`passivetotal.analyzer.IPAddress`
        """
        if getattr(self, '_current_ip', None) is not None:
            return self._current_ip
        return self._query_dns()
    
    @property
    def certificates(self):
        """List of certificates where this hostname is contained in the subjectAlternativeName field.

        Creates an instance of :class:`passivetotal.analyzer.ssl.CertificateField`
        and performs a certificate search.

        :rtype: :class:`passivetotal.analyzer.ssl.Certificates`
        """
        return CertificateField('subjectAlternativeName', self._hostname).certificates
   
    @property
    def whois(self):
        """Most recently available Whois record for the hostname's domain name.

        :rtype: :class:`passivetotal.analyzer.whois.DomainWhois`
        """
        if getattr(self, '_whois', None) is not None:
            return self._whois
        return self._api_get_whois(
            compact=False
        )


