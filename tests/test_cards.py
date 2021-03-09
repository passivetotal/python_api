from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.cards import CardsRequest


class CardsTestCase(unittest.TestCase):

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = CardsRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()
    
    def test_get_summary(self):
        response = self.client.get_summary(query='riskiq.net')
        assert('data_summary' in response)
        assert(response['data_summary']['projects']['count'] == 11)
    