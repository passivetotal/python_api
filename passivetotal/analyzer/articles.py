from datetime import datetime, timezone
from passivetotal.analyzer._common import (
    RecordList, Record
)
from passivetotal.analyzer import get_api



class ArticlesList(RecordList):
    """List of threat intelligence articles.
    
    Contains a list of :class:`passivetotal.analyzer.articles.Article` objects.
    """

    def _get_shallow_copy_fields(self):
        return ['_totalrecords']

    def _get_sortable_fields(self):
        return ['age','title','type']
    
    def _get_dict_fields(self):
        return ['totalrecords']
    
    @property
    def totalrecords(self):
        return self._totalrecords
    
    def parse(self, api_response):
        """Parse an API response."""
        self._totalrecords = api_response.get('totalRecords')
        self._records = []
        if api_response.get('articles', None) is not None:
            for article in api_response.get('articles', []):
                self._records.append(Article(article))
    
    def filter_tags(self, tags):
        """Filtered article list that includes articles with an exact match to one
        or more tags.

        Tests the `match_tags` method on each article.

        :param tags: String with one or multiple comma-separated tags, or a list
        :rtype: :class:`passivetotal.analyzer.articles.ArticlesList`
        """
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.match_tags(tags), self._records)
        return filtered_results
    
    def filter_text(self, text, fields=['tags','title','summary']):
        """Filtered article list that contain the text in one or more fields.
        
        Searches tags, title and summary by default - set `fields` param to a 
        smaller list to narrow the search.
        
        :param text: text to search for
        :param fields: list of fields to search (optional)
        :rtype: :class:`passivetotal.analyzer.articles.ArticlesList`
        """
        filtered_results = self._make_shallow_copy()
        filtered_results._records = filter(lambda r: r.match_text(text, fields), self._records)
        return filtered_results



class AllArticles(ArticlesList):
    """All threat intelligence articles currently published by RiskIQ.
    
    Contains a list of :class:`passivetotal.analyzer.articles.Article` objects.

    By default, instantiating the class will automatically load the entire list
    of threat intelligence articles. Pass autoload=False to the constructor to disable
    this functionality.
    """

    def __init__(self, autoload = True):
        """Initialize a list of articles; will autoload by default.

        :param autoload: whether to automatically load articles upon instantiation (defaults to true)
        """
        super().__init__()
        if autoload:
            self.load()

    def load(self):
        """Query the API for articles and load them into an articles list."""
        response = get_api('Articles').get_articles()
        self.parse(response)
    


class Article(Record):
    """A threat intelligence article."""

    def __init__(self, api_response):
        self._guid = api_response.get('guid')
        self._title = api_response.get('title')
        self._summary = api_response.get('summary')
        self._type = api_response.get('type')
        self._publishdate = api_response.get('publishDate')
        self._link = api_response.get('link')
        self._categories = api_response.get('categories')
        self._tags = api_response.get('tags')
        self._indicators = api_response.get('indicators')
    
    def __str__(self):
        return self.title
    
    def __repr__(self):
        return '<Article {}>'.format(self.guid)
    
    def _api_get_details(self):
        """Query the articles detail endpoint to fill in missing fields."""
        response = get_api('Articles').get_details(self._guid)
        self._summary = response.get('summary')
        self._publishdate = response.get('publishedDate')
        self._tags = response.get('tags')
        self._categories = response.get('categories')
        self._indicators = response.get('indicators')

    def _get_dict_fields(self):
        return ['guid','title','type','summary','str:date_published','age',
                 'link','categories','tags','indicators','indicator_count',
                 'indicator_types','str:ips','str:hostnames']

    def _ensure_details(self):
        """Ensure we have details for this article.

        Some API responses do not include full article details. This internal method
        will determine if they are missing and trigger an API call to fetch them."""
        if self._summary is None and self._publishdate is None:
            self._api_get_details()
    
    def _indicators_by_type(self, type):
        """Get indicators of a specific type. 

        Indicators are grouped by type in the API response. This method finds
        the group of a specified type and returns the dict of results directly
        from the API response. It assumes there is only one instance of a group
        type in the indicator list and therefore only returns the first one.
        """
        try:
            return [ group for group in self.indicators if group['type']==type][0]
        except IndexError:
            return {'type': None, 'count': 0, 'values': [] }
    
    def match_tags(self, tags):
        """Exact match search for one or more tags in this article's list of tags.

        :param tags: String with one or multiple comma-seperated tags, or a list
        :rtype bool: Whether any of the tags are included in this article's list of tags.
        """
        if type(tags) is str:
            tags = tags.split(',')
        return len(set(tags) & set(self.tags)) > 0
    
    def match_text(self, text, fields=['tags','title','summary']):
        """Case insensitive substring search across article text fields.

        Searches tags, title and summary by default - set `fields` param to a 
        smaller list to narrow the search.
        :param text: text to search for
        :param fields: list of fields to search (optional)
        :rtype bool: whether the text was found in any of the fields
        """
        for field in ['title','summary']:
            if field in fields:
                if text.casefold() in getattr(self, field).casefold():
                    return True
        if 'tags' in fields:
            for tag in self.tags:
                if text.casefold() in tag.casefold():
                    return True
        return False
   
    @property
    def guid(self):
        """Article unique ID within the RiskIQ system."""
        return self._guid
    
    @property
    def title(self):
        """Article short title."""
        return self._title
    
    @property
    def type(self):
        """Article visibility type (i.e. public, private)."""
        return self._type
    
    @property
    def summary(self):
        """Article summary."""
        self._ensure_details()
        return self._summary
    
    @property
    def date_published(self):
        """Date the article was published, as a datetime object."""
        self._ensure_details()
        date = datetime.fromisoformat(self._publishdate)
        return date
    
    @property
    def age(self):
        """Age of the article in days."""
        now = datetime.now(timezone.utc)
        interval = now - self.date_published
        return interval.days
    
    @property
    def link(self):
        """URL to a page with article details."""
        return self._link
    
    @property
    def categories(self):
        """List of categories this article is listed in."""
        self._ensure_details()
        return self._categories
    
    @property
    def tags(self):
        """List of tags attached to this article."""
        self._ensure_details()
        return self._tags
    
    def has_tag(self, tag):
        """Whether this article has a given tag."""
        return (tag in self.tags)
    
    @property
    def indicators(self):
        """List of indicators associated with this article.
        
        This is the raw result retuned by the API. Expect an array of objects each
        representing a grouping of a particular type of indicator."""
        self._ensure_details()
        return self._indicators
    
    @property
    def indicator_count(self):
        """Sum of all types of indicators in this article."""
        return sum([i['count'] for i in self.indicators])
    
    @property
    def indicator_types(self):
        """List of the types of indicators associated with this article."""
        return [ group['type'] for group in self.indicators ]
    
    @property
    def ips(self):
        """List of IP addresses in this article.

        :rtype: :class:`passivetotal.analyzer.ip.IPAddress`
        """
        from passivetotal.analyzer import IPAddress
        return [ IPAddress(ip) for ip in self._indicators_by_type('ip')['values'] ]
    
    @property
    def hostnames(self):
        """List of hostnames in this article.

        :rtype: :class:`passivetotal.analyzer.ip.Hostname`
        """
        from passivetotal.analyzer import Hostname
        return [ Hostname(domain) for domain in self._indicators_by_type('domain')['values'] ]



class HasArticles:

    """An object which may be an indicator of compromise (IOC) published in an Article."""

    def _api_get_articles(self):
        """Query the articles API for articles with this entity listed as an indicator."""
        response = get_api('Articles').get_articles_for_indicator(
            self.get_host_identifier()
        )
        self._articles = ArticlesList(response)
        return self._articles
    
    @property
    def articles(self):
        """Threat intelligence articles that reference this host.

        :rtype: :class:`passivetotal.analyzer.articles.ArticlesList`
        """
        if getattr(self, '_articles', None) is not None:
            return self._articles
        return self._api_get_articles()