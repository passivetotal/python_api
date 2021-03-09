from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.account import AccountClient


class AccountTestCase(unittest.TestCase):

    """Test case for account methods."""

    test_user = 'jdoe@passivetotal.org'

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = AccountClient('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()

    def test_account_details(self):
        response = self.client.get_account_details()
        assert (response.get('firstName', '')) == 'John'
        assert (response.get('lastName', '')) == 'Doe'
        assert (response.get('organization', '')) == 'PassiveTotal'
    
    def test_account_quota(self):
        response = self.client.get_account_quota()
        assert('user' in response)
        assert (response['user']['limits']['basic_monitors'] == 100)
        assert('organization' in response)
        assert (response['organization']['quotaInterval'] == 'daily')
        

    def test_account_history(self):
        response = self.client.get_account_history()
        assert('history' in response)
        assert(response['history'][0]['username']) == self.test_user

    def test_account_monitors(self):
        response = self.client.get_account_monitors()
        assert('monitors' in response)
        assert(response['monitors'][0]['focus']) == "37.139.30.161"

    def test_account_notifications(self):
        response = self.client.get_account_notifications()
        assert('notifications' in response)
        assert(response['notifications'][0]['username']) == self.test_user

    def test_account_sources(self):
        response = self.client.get_account_sources()
        assert('sources' in response)
        assert(response['sources'][0]['source']) == 'riskiq'

    def test_account_organization(self):
        response = self.client.get_account_organization()
        assert(response['admins'][0]) == 'admin@passivetotal.org'

    def test_account_organization_teamstream(self):
        response = self.client.get_account_organization_teamstream()
        assert('teamstream' in response)
        assert(response['teamstream'][0]['username']) == self.test_user
