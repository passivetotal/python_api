"""Hostname analyzer for the RiskIQ PassiveTotal API."""

import socket
from passivetotal.analyzer import get_api, get_config
from passivetotal.analyzer.pdns import PdnsResolutions
from passivetotal.analyzer.whois import DomainWhois
from passivetotal.analyzer.summary import HostnameSummary
from passivetotal.analyzer.ssl import CertificateField
from passivetotal.analyzer.ip import IPAddress



class Hostname(object):

    """Represents a hostname such as api.passivetotal.org.
    
    Instances are stored as class members so subsequent
    instantiations for the same hostname return the same object.

    Because of this, storing instances in variables is optional, which
    can be especially useful in interactive sessions such as Jupyter notebooks.
    
    """

    _instances = {}

    def __new__(cls, hostname):
        """Create or find an instance for the given hostname."""
        self = cls._instances.get(hostname)
        if self is None:
            self = cls._instances[hostname] = object.__new__(Hostname)
            self._hostname = hostname
            self._current_ip = None
            self._whois = None
            self._resolutions = None
            self._summary = None
            self._cookie_addresses = None
            self._cookie_hosts = None
        return self
    
    def __str__(self):
        return self._hostname
    
    def __repr__(self):
        return "Hostname('{}')".format(self.hostname)
    
    def _api_get_resolutions(self, unique=False, start_date=None, end_date=None, timeout=None, sources=None):
        """Query the pDNS API for resolution history."""
        meth = get_api('DNS').get_unique_resolutions if unique else get_api('DNS').get_passive_dns
        response = meth(
            query=self._hostname,
            start=start_date,
            end=end_date,
            timeout=timeout,
            sources=sources
        )
        self._resolutions = PdnsResolutions(response)
        return self._resolutions

    def _api_get_summary(self):
        """Query the Cards API for summary data."""
        response = get_api('Cards').get_summary(query=self._hostname)
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
        self._current_ip = IPAddress(ip)
        return self._current_ip
    
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
        if getattr(self, '_current_ip'):
            return self._current_ip
        return self._query_dns()
    
    @property
    def resolutions(self):
        """ List of pDNS resolutions where hostname was the DNS query value.
            
        Bounded by dates set in :meth:`passivetotal.analyzer.set_date_range`.
        
        Provides list of :class:`passivetotal.analyzer.pdns.PdnsRecord` objects.

        :rtype: :class:`passivetotal.analyzer.pdns.PdnsResolutions`
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
    def certificates(self):
        """List of certificates where this hostname is contained in the subjectAlternativeName field.

        Creates an instance of :class:`passivetotal.analyzer.ssl.CertificateField`
        and performs a certificate search.

        :rtype: :class:`passivetotal.analyzer.ssl.Certificates`
        """
        return CertificateField('subjectAlternativeName', self._hostname).certificates
        
    @property
    def summary(self):
        """Summary of PassiveTotal data available for this hostname.
        
        :rtype: :class:`passivetotal.analyzer.summary.HostnameSummary`
        """
        if getattr(self, '_summary'):
            return self._summary
        return self._api_get_summary()
    
    @property
    def whois(self):
        """Most recently available Whois record for the hostname's domain name.

        :rtype: :class:`passivetotal.analyzer.whois.DomainWhois`
        """
        if getattr(self, '_whois'):
            return self._whois
        return self._api_get_whois(
            compact=False
        )


