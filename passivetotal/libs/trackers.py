"""RiskIQ Illuminate API Interface."""

from textwrap import TextWrapper
from passivetotal.api import Client
from passivetotal.response import Response
from passivetotal.common import utilities


class TrackerRequest(Client):

    """Client to interface with the RiskIQ Trackers API."""

    TIMEOUT = 60

    def search_trackers(self, value, tracker_type, page=0, sort='lastSeen', order='desc', result_type='addresses'):
        """Search for trackers of a specific type and value and return either IP addresses or hostnames
        where that tracker has been observed.
        
        :param value: Value of the tracker (required)
        :param tracker_type: Type of the tracker (required)
        :param page: Page to return (defaults to 0 which returns the first 2,000 results)
        :param sort: Sort field for the results (must be "lastSeen" or "firstSeen", defaults to "lastSeen"
        :param order: Order to sort results on (must be "desc" or "asc", defaults to "desc")
        :param result_type: Type of results to return (must be "addresses" or "hosts", defaults to "addresses")
        """
        if result_type not in ['addresses','hosts']:
            raise AttributeError('result_type must be "addresses" or "hosts"')
        return self._get('trackers', value, result_type, type=tracker_type, page=page, sort=sort, order=order)
