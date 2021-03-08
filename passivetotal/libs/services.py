"""PassiveTotal API Interface."""

from passivetotal.api import Client
from passivetotal.response import Response



class ServicesRequest(Client):

    """Client to interface with the service calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(ServicesRequest, self).__init__(*args, **kwargs)

    def get_services(self, **kwargs):
        """Get services for an ip.

        Reference: https://api.passivetotal.org/index.html#api-Services-GetV2Services

        :param query: IP to search
        :return: Dict of results
        """
        return self._get('services', '', **kwargs)



class ServicesResponse(Response):
    pass