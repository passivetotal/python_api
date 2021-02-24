import unittest
from unittest.mock import patch

from .conf import fake_request

from passivetotal.libs.actions import ActionsClient
from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_VALUE_TYPE


class ActionsTestCase(unittest.TestCase):

    """Test case for action methods."""

    def setUp(self):
        self.patch_get = patch('passivetotal.api.Client._get', fake_request)
        self.patch_set = patch('passivetotal.api.Client._send_data', fake_request)
        self.patch_get.start()
        self.patch_set.start()
        self.client = ActionsClient('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patch_get.stop()
        self.patch_set.stop()

    def test_dynamic_dns(self):
        """Test various actions for dynamic DNS."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_dynamic_dns_status(**payload)
        assert not (response['dynamicDns'])

        payload = {'query': 'passivetotal.org', 'status': 'false'}
        response = self.client.set_dynamic_dns_status(**payload)
        assert not (response['dynamicDns'])

        with self.assertRaises(MISSING_FIELD) as cm:
            def missing_field():
                payload = {'query': 'passivetotal.org', 'no-status': 'false'}
                self.client.set_dynamic_dns_status(**payload)
            missing_field()
        assert 'field is required' in str(cm.exception)

    def test_sinkhole(self):
        """Test various actions for sinkhole."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_sinkhole_status(**payload)
        assert not (response['sinkhole'])

        payload = {'query': 'passivetotal.org', 'status': 'false'}
        response = self.client.set_sinkhole_status(**payload)
        assert not (response['sinkhole'])

        with self.assertRaises(MISSING_FIELD) as cm:
            def missing_field():
                payload = {'query': 'passivetotal.org', 'no-status': 'false'}
                self.client.set_sinkhole_status(**payload)
            missing_field()
        assert 'field is required' in str(cm.exception)

    def test_ever_compromised(self):
        """Test various actions for ever compromised."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_ever_compromised_status(**payload)
        assert not (response['everCompromised'])

        payload = {'query': 'passivetotal.org', 'status': 'false'}
        response = self.client.set_ever_compromised_status(**payload)
        assert not (response['everCompromised'])

        with self.assertRaises(MISSING_FIELD) as cm:
            def missing_field():
                payload = {'query': 'passivetotal.org', 'no-status': 'false'}
                self.client.set_ever_compromised_status(**payload)
            missing_field()
        assert 'field is required' in str(cm.exception)

    def test_monitor(self):
        """Test various actions for monitors."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_monitor_status(**payload)
        assert not (response['monitor'])

        payload = {'query': 'passivetotal.org', 'status': 'false'}
        response = self.client.set_monitor_status(**payload)
        assert not (response['monitor'])

        with self.assertRaises(MISSING_FIELD) as cm:
            def missing_field():
                payload = {'query': 'passivetotal.org', 'no-status': 'false'}
                self.client.set_monitor_status(**payload)
            missing_field()
        assert 'field is required' in str(cm.exception)

    def test_classification(self):
        """Test various actions for classifications."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_classification_status(**payload)
        assert (response['classification']) == 'non-malicious'

        payload = {'query': 'passivetotal.org',
                   'classification': 'non-malicious'}
        response = self.client.set_classification_status(**payload)
        assert (response['classification']) == 'non-malicious'

        with self.assertRaises(MISSING_FIELD) as cm:
            def missing_field():
                payload = {'query': 'passivetotal.org',
                           'no-classification': 'unknown'}
                self.client.set_classification_status(**payload)
            missing_field()
        assert 'field is required' in str(cm.exception)

        with self.assertRaises(INVALID_VALUE_TYPE) as cm:
            def invalid_field():
                payload = {'query': 'passivetotal.org', 'classification': '_'}
                self.client.set_classification_status(**payload)
            invalid_field()
        assert 'must be one of the following' in str(cm.exception)

    def test_tags(self):
        """Test various actions for tags."""
        payload = {'query': 'passivetotal.org'}
        response = self.client.get_tags(**payload)
        assert (response['tags'])
        assert ('security' in response['tags'])

        payload = {'query': 'passivetotal.org', 'tags': 'vendor,security'}
        response = self.client.add_tags(**payload)
        assert (response['tags'])
        response = self.client.remove_tags(**payload)
        assert (response['tags'])
        response = self.client.set_tags(**payload)
        assert (response['tags'])

        with self.assertRaises(INVALID_VALUE_TYPE) as cm:
            def invalid_field():
                payload = {'query': 'passivetotal.org', 'tags': {}}
                self.client.add_tags(**payload)
            invalid_field()
        assert 'must be a list' in str(cm.exception)


