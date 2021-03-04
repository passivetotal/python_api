"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.api import Client
# exceptions
from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_FIELD_TYPE
# const
from passivetotal.common.const import TRACKER_VALID_FIELDS


class HostAttributeRequest(Client):

    """Client to interface with the host attribute calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(HostAttributeRequest, self).__init__(*args, **kwargs)

    def get_components(self, **kwargs):
        """Get component data for a value.

        Reference: http://api.passivetotal.org/api/docs/#api-Host_Attributes-GetV2HostAttributesComponents

        :param query: Value to enrich
        :return: Dict of results
        """
        return self._get('host-attributes', 'components', **kwargs)

    def get_trackers(self, **kwargs):
        """Get tracker data for a value.

        Reference: http://api.passivetotal.org/api/docs/#api-Host_Attributes-GetV2HostAttributesTrackers

        :param query: Value to enrich
        :return: Dict of results
        """
        return self._get('host-attributes', 'trackers', **kwargs)

    def get_host_pairs(self, **kwargs):
        """Get host pair data for a value.

        Reference: http://api.passivetotal.org/api/docs/#api-Host_Attributes-GetV2HostAttributesPairs

        :param query: Value to enrich
        :return: Dict of results
        """
        return self._get('host-attributes', 'pairs', **kwargs)

    def get_cookies(self, **kwargs):
        """Get host pair data for a value.

        Reference: https://api.passivetotal.org/index.html#api-Host_Attributes-GetV2HostAttributesCookies

        :param query: Value to enrich
        :return: Dict of results
        """
        return self._get('host-attributes', 'cookies', **kwargs)

    def search_trackers_by_type(self, **kwargs):
        """Search trackers based on query value and type.

        Reference: http://api.passivetotal.org/api/docs/#api-Trackers-GetV2TrackersSearch

        :param str query: Query value to use when making the request for data
        :param str type: Field to run the query against
        :return: Tracker matches
        """
        if 'type' not in kwargs:
            raise MISSING_FIELD("Type value is required.")
        if kwargs['type'] not in WHOIS_VALID_FIELDS:
            raise INVALID_FIELD_TYPE("Field must be one of the following: %s"
                                     % ', '.join(TRACKER_VALID_FIELDS))
        return self._get('trackers', 'search', **kwargs)
