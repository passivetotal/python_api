#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.api import Client


class AccountClient(Client):

    """Client to interface with the account calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(AccountClient, self).__init__(*args, **kwargs)

    def get_account_details(self):
        """Get details about the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccount

        :return: Dict of account data
        """
        return self._get('account', '')

    def get_account_history(self):
        """Get history from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountHistory

        :return: Dict of history data
        """
        return self._get('account', 'history')

    def get_account_notifications(self):
        """Get notifications from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountNotifications

        :return: Dict of notifications data
        """
        return self._get('account', 'notifications')

    def get_account_sources(self):
        """Get sources from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountSourcesSource

        :return: Dict of source data
        """
        return self._get('account', 'sources')

    def get_account_organization(self):
        """Get organization data from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountOrganization

        :return: Dict of organization data
        """
        return self._get('account', 'organization')

    def get_account_organization_teamstream(self):
        """Get organization teamstream from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountOrganizationTeamstream

        :return: Dict of organization teamstream data
        """
        return self._get('account', 'organization', 'teamstream')