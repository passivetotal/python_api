from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.enrichment import EnrichmentRequest
from passivetotal.response import Response


class EnrichmentTestCase(unittest.TestCase):

    """Test case for DNS methods."""

    formats = ['json', 'xml', 'csv', 'text', 'table']

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = EnrichmentRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()

    def test_enrichment(self):
        """Test various actions for enrichment."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_enrichment(**payload)
        assert(response['queryValue'])

    def test_process_enrichment(self):
        """Test processing enrichment data."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_enrichment(**payload)
        wrapped = Response(response)
        assert (wrapped.queryValue) == 'passivetotal.org'

    def test_osint(self):
        """Test getting unique passive DNS records."""
        payload = {'query': 'xxxvideotube.org'}
        response = self.client.get_osint(**payload)
        wrapped = Response(response)
        assert (response['results'])
        record = wrapped.results.pop(0)
        record = Response(record)
        assert (record.source) == 'RiskIQ'
        assert (record.sourceUrl) == "https://www.riskiq.com/blog/riskiq-labs/post/a-brief-encounter-with-slempo"

    def test_malware(self):
        """Test processing malware."""
        payload = {'query': 'noorno.com'}
        response = self.client.get_malware(**payload)
        wrapped = Response(response)
        assert (response['results'])
        record = wrapped.results.pop(0)
        record = Response(record)
        assert (record.source) == 'Threatexpert'
        assert (record.sample) == "7ebf1e2d0c89b1c8124275688c9e8e98"

    def test_subdomains(self):
        """Test processing subdomains."""
        payload = {'query': '*.passivetotal.org'}
        response = self.client.get_subdomains(**payload)
        wrapped = Response(response)
        assert (wrapped.queryValue) == '*.passivetotal.org'
        assert ('www' in wrapped.subdomains)
