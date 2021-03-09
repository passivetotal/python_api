from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.services import ServicesRequest


class ServicesTestCase(unittest.TestCase):

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = ServicesRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()
    
    def test_get_services(self):
        response = self.client.get_services()
        assert('results' in response)
        assert(response['results'][0]['portNumber'] == 80)
        assert(type(response['results'][1]['currentServices']) == list)
    