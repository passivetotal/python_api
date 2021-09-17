from collections import OrderedDict
from functools import total_ordering

from passivetotal.analyzer import get_api
from passivetotal.analyzer._common import AsDictionary, ForPandas



@total_ordering
class ReputationScore(AsDictionary, ForPandas):

    """RiskIQ Illuminate Reputation profile for a hostname or an IP."""

    def __init__(self, api_response, query=None):
        self._response = api_response
        self._query = query
    
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
    
    def to_dataframe(self, explode_rules=False, drop_links=False):
        """Render this object as a Pandas DataFrame.

        :param explode_rules: Whether to create a row for each rule using `pandas.DataFrame.explode` (optional, defaults to False)
        :param drop_links: Whether to include links when present in exploded rules (optional, defaults to False)
        :rtype: :class:`pandas.DataFrame`
        """
        pd = self._get_pandas()
        as_d = OrderedDict(
            query       = self._query,
            score       = self.score,
            classification = self.classification,
            rules = self.rules
        )
        df = pd.DataFrame([as_d])
        if not explode_rules:
            return df
        df_rules = df.explode('rules', ignore_index=True)
        df_wide = pd.concat([df_rules.drop('rules', axis='columns'), df_rules['rules'].apply(pd.Series)], axis='columns')
        if drop_links:
            return df_wide.drop('link', axis='columns')
        return df_wide


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
        query=self.get_host_identifier()
        response = get_api('Illuminate').get_reputation(query=query)
        self._reputation = ReputationScore(response, query)
        return self._reputation

    @property
    def reputation(self):
        """RiskIQ Illuminate Reputation profile for a hostname or IP.

        :rtype: :class:`passivetotal.analyzer.illuminate.reputation.ReputationScore`
        """
        if getattr(self, '_reputation', None) is not None:
            return self._reputation
        return self._api_get_reputation()