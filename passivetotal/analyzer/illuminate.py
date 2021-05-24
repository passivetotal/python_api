from datetime import datetime
import pprint
from functools import total_ordering
from passivetotal.analyzer import get_api, get_config
from passivetotal.analyzer._common import AsDictionary


@total_ordering
class ReputationScore(AsDictionary):

    """RiskIQ Illuminate Reputation profile for a hostname or an IP."""

    def __init__(self, api_response):
        self._response = api_response
    
    def __str__(self):
        return '{0.score} ({0.classification})'.format(self)
    
    def __repr__(self):
        return '<ReputationScore {0.score} "{0.classification}">'.format(self)
    
    def __int__(self):
        return self.score
    
    def __gt__(self, other):
        return self.score > other
    
    def __eq__(self, other):
        return self.score == other
    
    @property
    def as_dict(self):
        """Representation as a dictionary object."""
        return {
            'score': self.score,
            'classification': self.classification,
            'rules': self.rules,
        }

    @property
    def score(self):
        """Reputation score as an integer ranging from 0-100.

        Higher values indicate a greater likelihood of maliciousness.
        """
        return self._response.get('score')
    
    @property
    def classification(self):
        """Reputation classification as a string. 

        Typical values include GOOD, SUSPICIOUS, MALICIOUS, or UNKNOWN.
        """
        return self._response.get('classification')
    
    @property
    def rules(self):
        """List of rules that informed the reputation score.

        Returns a list of dictionaries.
        """
        return self._response.get('rules')



class HasReputation:

    """An object with a RiskIQ Illuminate Reputation score."""

    def _api_get_reputation(self):
        """Query the reputation endpoint."""

        response = get_api('Illuminate').get_reputation(
            query=self.get_host_identifier()
        )
        self._reputation = ReputationScore(response)
        return self._reputation

    @property
    def reputation(self):
        """RiskIQ Illuminate Reputation profile for a hostname or IP.

        :rtype: :class:`passivetotal.analyzer.illuminate.ReputationScore`
        """
        if getattr(self, '_reputation', None) is not None:
            return self._reputation
        return self._api_get_reputation()