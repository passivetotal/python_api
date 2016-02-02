import pytest
from mock import patch
import unittest

from conf import fake_request
from passivetotal.libs.ssl import SslRequest
from passivetotal.libs.ssl import SslResponse
from passivetotal.libs.ssl import SslHistoryResponse
from passivetotal.libs.ssl import SslSearchResponse

from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_FIELD_TYPE


class SslTestCase(unittest.TestCase):

    """Test case for SSL certificate methods."""

    formats = ['json', 'xml', 'csv', 'text', 'table']

    def setup_class(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = SslRequest('--No-User--', '--No-Key--')

    def teardown_class(self):
        self.patcher.stop()

    def test_ssl_certificate_details(self):
        """Test getting SSL certificate details."""
        payload = {'query': 'e9a6647d6aba52dc47b3838c920c9ee59bad7034'}
        response = self.client.get_ssl_certificate_details(**payload)
        assert (response.get('serialNumber')) == '2317683628587350290823564500811277499'

    def test_process_ssl_certificate_details(self):
        """Test processing SSL certificate details."""
        payload = {'query': 'e9a6647d6aba52dc47b3838c920c9ee59bad7034'}
        response = self.client.get_ssl_certificate_details(**payload)
        wrapped = SslResponse(response)
        for item in self.formats:
            assert (getattr(wrapped, item))

    def test_property_load(self):
        """Test loading properties on a result."""
        payload = {'query': 'e9a6647d6aba52dc47b3838c920c9ee59bad7034'}
        response = self.client.get_ssl_certificate_details(**payload)
        wrapped = SslResponse(response)

        for key, value in response.iteritems():
            assert (getattr(wrapped, key)) == value

    def test_ssl_certificate_search(self):
        """Test getting a SSL certificate search."""
        payload = {'query': 'www.passivetotal.org', 'field': 'subject_commonName'}
        response = self.client.search_ssl_certificate_by_field(**payload)
        assert (response['results'][0]['serialNumber']) == '19322308692400755425805651738750646013'

    def test_ssl_certificate_search_bad_field(self):
        """Test sending a bad field in a search."""
        with pytest.raises(INVALID_FIELD_TYPE) as excinfo:
            def invalid_field():
                payload = {'query': 'www.passivetotal.org', 'field': '_'}
                self.client.search_ssl_certificate_by_field(**payload)
            invalid_field()
        assert 'must be one of the following' in str(excinfo.value)

    def test_ssl_certificate_search_missing_field(self):
        """Test missing a field in a search."""
        with pytest.raises(MISSING_FIELD) as excinfo:
            def missing_field():
                payload = {'query': 'www.passivetotal.org', 'no-field': '_'}
                self.client.search_ssl_certificate_by_field(**payload)
            missing_field()
        assert 'value is required' in str(excinfo.value)

    def test_process_ssl_certificate_search(self):
        """Test processing search results."""
        payload = {'query': 'www.passivetotal.org', 'field': 'subject_commonName'}
        response = self.client.search_ssl_certificate_by_field(**payload)
        results = SslSearchResponse(response)
        assert (results.get_records()[0].serialNumber) == '19322308692400755425805651738750646013'

    def test_process_ssl_certificate_history(self):
        """Test processing search results."""
        payload = {'query': '52.8.228.23'}
        response = self.client.get_ssl_certificate_history(**payload)
        wrapped = SslHistoryResponse(response)
        record = wrapped.get_records().pop(0)
        assert (record.sha1) == 'e9a6647d6aba52dc47b3838c920c9ee59bad7034'
