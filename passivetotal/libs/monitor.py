"""PassiveTotal API Interface."""

from passivetotal.api import Client
from passivetotal.response import Response


class MonitorRequest(Client):

    """Client to interface with the Monitor API calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super().__init__(*args, **kwargs)

    def get_alerts(self, **kwargs):
        """Get alerts for a given project or artifact.

        Either project or artifact must be provided.

        Reference: https://api.riskiq.net/api/monitor/#!/default/get_pt_v2_monitor

        :param project: filter project GUID
        :param artifact: filter by artifact GUID
        :param start: filter by start date, in yyyy-MM-dd HH:mm:ss format
        :param end: filter by end date, in yyyy-MM-dd HH:mm:ss format
        :param size: max number of results, default is 25
        :param page: page number of results to retrieve
        :return: Dict of results
        """
        return self._get('monitor', '', **kwargs)



class ArtifactsResponse(Response):
    pass