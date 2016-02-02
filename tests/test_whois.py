import pytest
from mock import patch
import unittest

from conf import fake_request
from passivetotal.libs.whois import WhoisRequest
from passivetotal.libs.whois import WhoisResponse
from passivetotal.libs.whois import WhoisSearchResponse

from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_FIELD_TYPE


class WhoisTestCase(unittest.TestCase):

    """Test case for WHOIS methods."""

    formats = ['json', 'xml', 'csv', 'text', 'table']

    def setup_class(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = WhoisRequest('--No-User--', '--No-Key--')

    def teardown_class(self):
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
        wrapped = WhoisResponse(response)
        assert (wrapped.get_days_since_registration()) == 17470
        assert (wrapped.get_days_since_updated()) == 17470
        assert (wrapped.get_days_until_expiration()) == 17470
        for item in self.formats:
            assert (getattr(wrapped, item))

    def test_property_load(self):
        """Test loading properties on a result."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_whois_details(**payload)
        wrapped = WhoisResponse(response)

        for key, value in response.iteritems():
            assert (getattr(wrapped, key)) == value

    def test_whois_search(self):
        """Test getting a WHOIS search."""
        payload = {'query': '18772064254', 'field': 'phone'}
        response = self.client.search_whois_by_field(**payload)
        assert (response['results'][0].get('domain')) == 'passivetotal.org'

    def test_whois_search_bad_field(self):
        """Test sending a bad field in a search."""
        with pytest.raises(INVALID_FIELD_TYPE) as excinfo:
            def invalid_field():
                payload = {'query': '18772064254', 'field': '_'}
                self.client.search_whois_by_field(**payload)
            invalid_field()
        assert 'must be one of the following' in str(excinfo.value)

    def test_whois_search_missing_field(self):
        """Test missing a field in a search."""
        with pytest.raises(MISSING_FIELD) as excinfo:
            def missing_field():
                payload = {'query': '18772064254', 'no-field': '_'}
                self.client.search_whois_by_field(**payload)
            missing_field()
        assert 'value is required' in str(excinfo.value)

    def test_process_whois_search(self):
        """Test processing search results."""
        payload = {'query': '18772064254', 'field': 'phone'}
        response = self.client.search_whois_by_field(**payload)
        results = WhoisSearchResponse(response)
        assert (results.get_records()[0].domain) == 'passivetotal.org'
