"""PassiveTotal API Interface."""

from passivetotal.api import Client
from passivetotal.response import Response


class CookiesRequest(Client):

    """Client to interface with the Cookies API calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(CookiesRequest, self).__init__(*args, **kwargs)

    def get_addresses_by_domain(self, domain, **kwargs):
        """Get cookies addresses information by cookie domain

        Reference: https://api.passivetotal.org/index.html#api-Cookies-GetV2CookiesDomainDomainAddresses

        :param domain: Domain to search
        :param page: Page number for results, optional
        :param sort: 'lastSeen' or 'firstSeen', optional
        :param order: 'asc' or 'desc', optional
        :return: Dict of results
        """
        return self._get('cookies', 'domain/{}/addresses'.format(domain), **kwargs)
    
    def get_addresses_by_name(self, cookie_name, **kwargs):
        """Get cookies addresses information by cookie name

        Reference: https://api.passivetotal.org/index.html#api-Cookies-GetV2CookiesNameNameAddresses

        :param cookie_name: Cookie name to search
        :param page: Page number for results, optional
        :param sort: 'lastSeen' or 'firstSeen', optional
        :param order: 'asc' or 'desc', optional
        :return: Dict of results
        """
        return self._get('cookies', 'name/{}/addresses'.format(cookie_name), **kwargs)
    
    def get_hosts_by_domain(self, domain, **kwargs):
        """Get cookies hostnames information by domain

        Reference: https://api.passivetotal.org/index.html#api-Cookies-GetV2CookiesNameNameAddresses

        :param domain: Domain to search
        :param page: Page number for results, optional
        :param sort: 'lastSeen' or 'firstSeen', optional
        :param order: 'asc' or 'desc', optional
        :return: Dict of results
        """
        return self._get('cookies', 'domain/{}/hosts'.format(domain), **kwargs)
    
    def get_hosts_by_name(self, cookie_name, **kwargs):
        """Get cookies hosts information by cookie name

        Reference: https://api.passivetotal.org/index.html#api-Cookies-GetV2CookiesNameNameHosts

        :param cookie_name: Cookie name to search
        :param page: Page number for results, optional
        :param sort: 'lastSeen' or 'firstSeen', optional
        :param order: 'asc' or 'desc', optional
        :return: Dict of results
        """
        return self._get('cookies', 'name/{}/hosts'.format(cookie_name), **kwargs)

class CookiesResponse(Response):
    pass