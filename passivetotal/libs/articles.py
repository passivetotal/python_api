"""PassiveTotal API Interface."""

from passivetotal.common import utilities
from passivetotal.api import Client
from passivetotal.response import Response


class ArticlesRequest(Client):

    """Client to interface with the Articles API calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(ArticlesRequest, self).__init__(*args, **kwargs)

    def get_articles(self, **kwargs):
        """Get all articles.

        Reference: https://api.passivetotal.org/index.html#api-Articles-GetV2Articles

        :param page: Page number for results, optional
        :param sort: order to sort - defaults to created, optional
        :param order: 'asc' or 'desc', optional
        :return: Dict of results
        """
        return self._get('articles', '', **kwargs)
    
    def get_details(self,article_guid):
        """Get article details.

        Reference: https://api.passivetotal.org/index.html#api-Articles-GetV2Articles

        :param article_guid: GUID of the article (from get_articles)
        :return: Dict of results
        """
        return self._get('articles', article_guid)
    
    def get_indicators(self, **kwargs):
        """Get article indicators ordered by publish date oldest to newest.

        Reference: https://api.passivetotal.org/index.html#api-Articles-GetV2ArticlesIndicators

        :param articleGuid: GUID of the article, optional
        :param startDate: Starting date in YYYY-MM-DD format, optional
        :return: Dict of results
        """
        return self._get('articles', 'indicators', **kwargs)



class ArticlesResponse(Response):
    pass



class ArticlesIndicatorResponse(Response):
    @property
    def csv(self):
        fields = ['type', 'value', 'guid', 'source', 'link', 'publishedDate', 'tags']
        def build_row():
            for result in self._results.get('indicators', []):
                yield [ result.get(field,'') for field in fields ]
        return utilities.to_csv(fields, build_row())