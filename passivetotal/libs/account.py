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

    def get_account_history(self, **kwargs):
        """Get history from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountHistory
        
        :param str source: History type (api/web) - defaults to both, optional
        :param str dt: Date to start showing results for, optional
        :param str focus: Query to filter for (domain, ip, etc), optional
        :return: Dict of history data
        """
        return self._get('account', 'history', **kwargs)

    def get_account_quota(self):
        """Get current account and organization quotas from the requesting account.

        Reference: https://api.passivetotal.org/index.html#api-Account-GetV2AccountQuota

        :return: Dict of quota data
        """
        return self._get('account', 'quota')

    def get_account_monitors(self):
        """Get monitors from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountMonitors

        :return: Dict of monitor data
        """
        return self._get('account', 'monitors')

    def get_account_notifications(self, **kwargs):
        """Get notifications from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountNotifications

        :return: Dict of notifications data
        """
        return self._get('account', 'notifications', **kwargs)

    def get_account_sources(self, **kwargs):
        """Get sources from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountSourcesSource

        :param str source: A source to filter on, optional
        :return: Dict of source data
        """
        return self._get('account', 'sources', **kwargs)

    def get_account_organization(self):
        """Get organization data from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountOrganization

        :return: Dict of organization data
        """
        return self._get('account', 'organization')

    def get_account_organization_teamstream(self, **kwargs):
        """Get organization teamstream from the requesting account.

        Reference: https://api.passivetotal.org/api/docs/#api-Account-GetAccountOrganizationTeamstream

        :param str source: Filter to this source, optional
        :param str dt: Filter to this datetime, optional
        :param str type: Filter by type field, optional
        :param str focus: Filter by focus (domain, ip, etc), optional
        :return: Dict of organization teamstream data
        """
        return self._get('account', 'organization', 'teamstream', **kwargs)


    def get_account_classifications(self, **kwargs):
        """Get account items with the specified classification.

        Reference: https://api.passivetotal.org/index.html#api-Account-GetV2AccountClassifications

        :param str classification: Classification to retrieve items for, optional
        :return: Dict of organization data
        """
        return self._get('account', 'classifications', **kwargs)