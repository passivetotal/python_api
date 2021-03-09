from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.articles import ArticlesRequest


class ArticlesTestCase(unittest.TestCase):

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = ArticlesRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()
    
    def test_get_articles(self):
        response = self.client.get_articles()
        assert('articles' in response)
        assert(response['articles'][0]['guid'] == "e86878b1")
        assert(type(response['articles'][0]['tags']) == list)
    
    def test_get_details(self):
        response = self.client.get_details('e86878b1')
        assert('guid' in response)
        assert(type(response['tags']) == list)
        assert(len(response['indicators']) > 0)

    def test_get_indicators(self):
        response = self.client.get_indicators(startDate='2021-03-01')
        assert('indicators' in response)
        assert(response['indicators'][1]['publishedDate'] == '2021-03-05T01:00:00.000+0000')

