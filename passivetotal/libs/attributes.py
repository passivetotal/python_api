"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.common.const import ATTRIBUTE_APPROVED_FIELDS as approved_fields
from passivetotal.api import Client
from passivetotal.response import Response
from passivetotal.common import utilities


class AttributeRequest(Client):

    """Client to interface with the Host Attribute calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(AttributeRequest, self).__init__(*args, **kwargs)

    def get_host_attribute_trackers(self, **kwargs):
        """Get trackers associated with a particular host or IP address.

        Reference: https://api.passivetotal.org/api/docs/#api-Host_Attributes-GetTrackers

        :return: Dict of results with tracking IDs
        """
        return self._get('host-attributes', 'trackers', **kwargs)

    def get_host_attribute_components(self, **kwargs):
        """Get components associated with a particular host or IP address.

        Reference: https://api.passivetotal.org/api/docs/#api-Host_Attributes-GetComponents

        :return: Dict of results with component information
        """
        return self._get('host-attributes', 'components', **kwargs)

    def get_host_attribute_pairs(self, **kwargs):
        """Get pairs associated with a particular hostname.

        Reference: https://api.passivetotal.org/api/docs/#api-Host_Attributes-GetV2HostAttributesPairsQuery

        :return: Dict of results with hostpairs information
        """
        return self._get('host-attributes', 'pairs', **kwargs)
    
    def get_host_attribute_cookies(self, **kwargs):
        """Get cookies associated with a particular hostname.

        Reference: https://api.passivetotal.org/index.html#api-Host_Attributes-GetV2HostAttributesCookies

        :return: Dict of results with cookies information
        """
        return self._get('host-attributes', 'cookies', **kwargs)

    def search_trackers(self, **kwargs):
        """Search tracking IDs for associated hosts.

        Reference: https://api.passivetotal.org/api/docs/#api-Host_Attributes-SearchTrackers

        :return: Dict of matching hosts using a tracking ID
        """
        return self._get('trackers', 'search', **kwargs)


class AttributeResponse(Response):
    @property
    def csv(self):
        data = []
        for record in self._results['results']:
            data.append([record.get(i) for i in approved_fields])
        return utilities.to_csv(approved_fields, data)
