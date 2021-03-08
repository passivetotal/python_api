"""PassiveTotal API Interface."""

from passivetotal.api import Client
from passivetotal.response import Response


class CardsRequest(Client):

    """Client to interface with the cards API calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(CardsRequest, self).__init__(*args, **kwargs)

    def get_summary(self, **kwargs):
        """Get services for an ip or domain.

        Reference: https://api.passivetotal.org/index.html#api-Data_Card-GetV2CardsSummary

        :param query: IP or domain to search
        :return: Dict of results
        """
        return self._get('cards', 'summary', **kwargs)

class CardsResponse(Response):
    pass
