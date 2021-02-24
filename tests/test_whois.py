from unittest.mock import patch
import unittest
from future.utils import iteritems

from .conf import fake_request
from passivetotal.libs.whois import WhoisRequest
from passivetotal.response import Response
from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_FIELD_TYPE


class WhoisTestCase(unittest.TestCase):

    """Test case for WHOIS methods."""

    formats = ['json']

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = WhoisRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()

    def test_whois_details(self):
        """Test getting WHOIS details."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_whois_details(**payload)
        assert (response.get('domain')) == 'passivetotal.org'

    def test_process_whois_details(self):
        """Test processing WHOIS details."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_whois_details(**payload)
        wrapped = Response(response)
        for item in self.formats:
            assert (getattr(wrapped, item))

    def test_property_load(self):
        """Test loading properties on a result."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_whois_details(**payload)
        wrapped = Response(response)

        for key, value in iteritems(response):
            assert (getattr(wrapped, key)) == value

    def test_whois_search(self):
        """Test getting a WHOIS search."""
        payload = {'query': '18772064254', 'field': 'phone'}
        response = self.client.search_whois_by_field(**payload)
        assert (response['results'][0].get('domain')) == 'passivetotal.org'

    def test_whois_search_bad_field(self):
        """Test sending a bad field in a search."""
        with self.assertRaises(INVALID_FIELD_TYPE) as cm:
            def invalid_field():
                payload = {'query': '18772064254', 'field': '_'}
                self.client.search_whois_by_field(**payload)
            invalid_field()
        assert 'must be one of the following' in str(cm.exception)

    def test_whois_search_missing_field(self):
        """Test missing a field in a search."""
        with self.assertRaises(MISSING_FIELD) as cm:
            def missing_field():
                payload = {'query': '18772064254', 'no-field': '_'}
                self.client.search_whois_by_field(**payload)
            missing_field()
        assert 'value is required' in str(cm.exception)

    def test_process_whois_search(self):
        """Test processing search results."""
        payload = {'query': '18772064254', 'field': 'phone'}
        response = self.client.search_whois_by_field(**payload)
        results = Response(response)
        assert (Response(results.results[0]).domain) == 'passivetotal.org'
