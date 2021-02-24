from unittest.mock import patch
import unittest
from future.utils import iteritems

from .conf import fake_request
from passivetotal.libs.ssl import SslRequest
from passivetotal.response import Response
from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_FIELD_TYPE


class SslTestCase(unittest.TestCase):

    """Test case for SSL certificate methods."""

    formats = ['json']

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = SslRequest('--No-User--', '--No-Key--')

    def tearDown(self):
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
        wrapped = Response(response)
        for item in self.formats:
            assert (getattr(wrapped, item))

    def test_property_load(self):
        """Test loading properties on a result."""
        payload = {'query': 'e9a6647d6aba52dc47b3838c920c9ee59bad7034'}
        response = self.client.get_ssl_certificate_details(**payload)
        wrapped = Response(response)

        for key, value in iteritems(response):
            assert (getattr(wrapped, key)) == value

    def test_ssl_certificate_search(self):
        """Test getting a SSL certificate search."""
        payload = {'query': 'www.passivetotal.org', 'field': 'subjectCommonName'}
        response = self.client.search_ssl_certificate_by_field(**payload)
        assert (response['results'][0]['serialNumber']) == '2317683628587350290823564500811277499'

    def test_ssl_certificate_search_bad_field(self):
        """Test sending a bad field in a search."""
        with self.assertRaises(INVALID_FIELD_TYPE) as cm:
            def invalid_field():
                payload = {'query': 'www.passivetotal.org', 'field': '_'}
                self.client.search_ssl_certificate_by_field(**payload)
            invalid_field()
        assert 'must be one of the following' in str(cm.exception)

    def test_ssl_certificate_search_missing_field(self):
        """Test missing a field in a search."""
        with self.assertRaises(MISSING_FIELD) as cm:
            def missing_field():
                payload = {'query': 'www.passivetotal.org', 'no-field': '_'}
                self.client.search_ssl_certificate_by_field(**payload)
            missing_field()
        assert 'value is required' in str(cm.exception)

    def test_process_ssl_certificate_search(self):
        """Test processing search results."""
        payload = {'query': 'www.passivetotal.org', 'field': 'subjectCommonName'}
        response = self.client.search_ssl_certificate_by_field(**payload)
        results = Response(response)
        assert (Response(results.results[0]).serialNumber) == '2317683628587350290823564500811277499'

    def test_process_ssl_certificate_history(self):
        """Test processing search results."""
        payload = {'query': '52.8.228.23'}
        response = self.client.get_ssl_certificate_history(**payload)
        wrapped = Response(response)
        record = Response(wrapped.results.pop(0))
        assert (record.sha1) == 'e9a6647d6aba52dc47b3838c920c9ee59bad7034'
