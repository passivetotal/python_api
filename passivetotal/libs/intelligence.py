"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.api import Client


class IntelligenceRequest(Client):

    """Client to interface with the intelligence calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(IntelligenceRequest, self).__init__(*args, **kwargs)

    def get_blacklisted(self, **kwargs):
        """Get blacklisted decision for a value.

        Reference:

        :param query: Value to enrich
        :return: Dict of results
        """
        return self._get('intelligence', 'blacklist', **kwargs)
