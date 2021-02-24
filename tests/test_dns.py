from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.dns import DnsRequest
from passivetotal.response import Response


class DnsTestCase(unittest.TestCase):

    """Test case for DNS methods."""

    formats = ['json']

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = DnsRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()

    def test_dns_passive(self):
        """Test getting passive DNS records."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_passive_dns(**payload)
        assert (response.get('queryValue')) == 'passivetotal.org'

    def test_process_dns_passive(self):
        """Test processing passive DNS records."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_passive_dns(**payload)
        wrapped = Response(response)
        assert (wrapped.queryValue) == 'passivetotal.org'
        assert (Response(wrapped.results.pop(0)).recordHash) == '6d24bc7754af023afeaaa05ac689ac36e96656aa6519ba435b301b14916b27d3'

    def test_dns_passive_unique(self):
        """Test getting unique passive DNS records."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_unique_resolutions(**payload)
        wrapped = Response(response)
        assert (wrapped.queryValue) == 'passivetotal.org'
        record = wrapped.frequency.pop(0)
        assert (record[0]) == '107.170.89.121'
        assert (record[1]) == 2
