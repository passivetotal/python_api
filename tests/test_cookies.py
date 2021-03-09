from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.cookies import CookiesRequest


class CookiesTestCase(unittest.TestCase):

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = CookiesRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()
    
    def test_get_hosts_by_domain(self):
        response = self.client.get_hosts_by_domain(domain='riskiq.net')
        assert('results' in response)
        assert(response['results'][1]['hostname'] == 'info.riskiq.net')
    