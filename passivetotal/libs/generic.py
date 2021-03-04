"""PassiveTotal API Interface.

This generic request is useful for new API endpoints that
are not yet directly supported in the other modules.

"""

from passivetotal.api import Client
from passivetotal.common.exceptions import INVALID_URL

class GenericRequest(Client):

    """Class to interface with any PassiveTotal API endpoint."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(GenericRequest, self).__init__(*args, **kwargs)
    
    def get(self, endpoint, action='', **params):
        """Make a generic request to the PassiveTotal API.

        :param endpoint: Endpoint without version, i.e. 'account'
        :param action: Additional endpoint URL segments if needed, i.e. 'quota' or 'whois/riskiq.net', optional
        :param params: Any additional key-value pairs to be passed to the API, optional
        :return: Dict of returned data
        """
        return self._get(endpoint, action, **params)
    
    def write(self, verb, endpoint, action='', data={}):
        """Write data to an arbitrary PassiveTotal API endpoint.

        :param verb: HTTP action - POST, PUT or DELETE
        :param endpoint: API endpoint without version, i.e. 'account'
        :param action: Additional endpoint URL segments if needed, optional
        :param data: Dict of data to write to the API endpoint, optional
        """
        return self._send_data(verb, endpoint, action, data)

