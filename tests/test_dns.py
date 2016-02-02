import pytest
from mock import patch
import unittest

from conf import fake_request
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.dns import DnsResponse
from passivetotal.libs.dns import DnsUniqueResponse


class DnsTestCase(unittest.TestCase):

    """Test case for DNS methods."""

    formats = ['json', 'xml', 'csv', 'text', 'table', 'stix']

    def setup_class(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = DnsRequest('--No-User--', '--No-Key--')

    def teardown_class(self):
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
        wrapped = DnsResponse(response)
        assert (wrapped.queryValue) == 'passivetotal.org'
        assert (wrapped.get_records().pop(0).recordHash) == '6d24bc7754af023afeaaa05ac689ac36e96656aa6519ba435b301b14916b27d3'
        assert (wrapped.get_days_until_now()) == 17469
        assert (wrapped.get_observed_days()) == 0
        assert (len(wrapped.get_source_variety().keys())) == 1

    def test_dns_passive_unique(self):
        """Test getting unique passive DNS records."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_unique_resolutions(**payload)
        wrapped = DnsUniqueResponse(response)
        assert (wrapped.queryValue) == 'passivetotal.org'
        record = wrapped.get_records().pop(0)
        assert (record.resolve) == '107.170.89.121'
        assert (record.count) == 2
