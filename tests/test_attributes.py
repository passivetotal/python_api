import pytest
from mock import patch
import unittest

from conf import fake_request
from passivetotal.libs.attributes import AttributeRequest
from passivetotal.libs.attributes import AttributeResponse


class AttributeTestCase(unittest.TestCase):

    """Test case for attribute methods."""

    formats = ['json', 'xml', 'csv', 'table']

    def setup_class(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = AttributeRequest('--No-User--', '--No-Key--')

    def teardown_class(self):
        self.patcher.stop()

    def test_trackers(self):
        """Test getting tracker codes."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_host_attribute_trackers(**payload)
        assert ('results' in response)

    def test_process_trackers(self):
        """Test processing tracker data."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_host_attribute_trackers(**payload)
        wrapped = AttributeResponse(response)
        record = wrapped.get_records().pop(0)
        assert (record.hostname) == 'passivetotal.org'
        assert (record.lastSeen) == '2016-01-26 13:47:45'
        assert (record.attributeType) == 'GoogleAnalyticsAccountNumber'
        assert (record.firstSeen) == '2015-10-09 17:05:38'
        assert (record.attributeValue) == 'UA-61048133'

    def test_components(self):
        """Test getting component data."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_host_attribute_components(**payload)
        assert ('results' in response)

    def test_process_components(self):
        """Test processing component data."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_host_attribute_components(**payload)
        wrapped = AttributeResponse(response)
        record = wrapped.get_records().pop(0)
        assert (record.hostname) == 'passivetotal.org'
        assert (record.lastSeen) == '2016-01-07 21:52:30'
        assert (record.category) == 'JavaScript Library'
        assert (record.firstSeen) == '2015-12-26 11:17:43'
        assert (record.label) == 'jQuery'

    def test_trackers_search(self):
        """Test searching trakcer data."""
        payload = {'query': 'UA-49901229', 'type': 'GoogleAnalyticsAccountNumber'}
        response = self.client.search_trackers(**payload)
        assert ('results' in response)

    def test_process_trackers_search(self):
        """Test processing component data."""
        payload = {'query': 'UA-49901229', 'type': 'GoogleAnalyticsAccountNumber'}
        response = self.client.search_trackers(**payload)
        wrapped = AttributeResponse(response)
        record = wrapped.get_records().pop(0)
        assert not (record.everBlacklisted)
        assert (record.alexaRank) == 38
        assert (record.hostname) == 'demo.paypal.com'
