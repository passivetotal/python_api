#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

from passivetotal.api import Client
# exceptions
from passivetotal.common.exceptions import MISSING_FIELD
from passivetotal.common.exceptions import INVALID_VALUE_TYPE
# const
from passivetotal.common.const import ACTIONS
from passivetotal.common.const import ACTIONS_CLASSIFICATION
from passivetotal.common.const import ACTIONS_DYNAMIC_DNS
from passivetotal.common.const import ACTIONS_EVER_COMPROMISED
from passivetotal.common.const import ACTIONS_MONITOR
from passivetotal.common.const import ACTIONS_SINKHOLE
from passivetotal.common.const import ACTIONS_TAG
from passivetotal.common.const import CLASSIFICATION_VALID_VALUES
from passivetotal.common.const import ENRICHMENT


class ActionsClient(Client):

    """Client to interface with the Actions calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(ActionsClient, self).__init__(*args, **kwargs)

    def get_dynamic_dns_status(self, **kwargs):
        return self._get(ACTIONS, ACTIONS_DYNAMIC_DNS, **kwargs)

    def set_dynamic_dns_status(self, **kwargs):
        if 'status' not in kwargs:
            raise MISSING_FIELD("Status field is required.")
        # if type(kwargs['status']) != bool:
        #     raise INVALID_VALUE_TYPE("Status must be type bool.")
        data = {'status': kwargs['status'], 'query': kwargs['query']}
        return self._send_data('POST', ACTIONS, ACTIONS_DYNAMIC_DNS, data)

    def get_ever_compromised_status(self, **kwargs):
        return self._get(ACTIONS, ACTIONS_EVER_COMPROMISED, **kwargs)

    def set_ever_compromised_status(self, **kwargs):
        if 'status' not in kwargs:
            raise MISSING_FIELD("Status field is required.")
        # if type(kwargs['status']) != bool:
        #     raise INVALID_VALUE_TYPE("Status must be type bool.")
        data = {'status': kwargs['status'], 'query': kwargs['query']}
        return self._send_data('POST', ACTIONS, ACTIONS_EVER_COMPROMISED, data)

    def get_sinkhole_status(self, **kwargs):
        return self._get(ACTIONS, ACTIONS_SINKHOLE, **kwargs)

    def set_sinkhole_status(self, **kwargs):
        if 'status' not in kwargs:
            raise MISSING_FIELD("Status field is required.")
        # if type(kwargs['status']) != bool:
        #     raise INVALID_VALUE_TYPE("Status must be type bool.")
        data = {'status': kwargs['status'], 'query': kwargs['query']}
        return self._send_data('POST', ACTIONS, ACTIONS_SINKHOLE, data)

    def get_monitor_status(self, **kwargs):
        return self._get(ACTIONS, ACTIONS_MONITOR, **kwargs)

    def set_monitor_status(self, **kwargs):
        if 'status' not in kwargs:
            raise MISSING_FIELD("Status field is required.")
        # if type(kwargs['status']) != bool:
        #     raise INVALID_VALUE_TYPE("Status must be type bool.")
        data = {'status': kwargs['status'], 'query': kwargs['query']}
        return self._send_data('POST', ACTIONS, ACTIONS_MONITOR, data)

    def get_classification_status(self, **kwargs):
        return self._get(ACTIONS, ACTIONS_CLASSIFICATION, **kwargs)

    def set_classification_status(self, **kwargs):
        if 'classification' not in kwargs:
            raise MISSING_FIELD("Classification field is required.")
        if kwargs['classification'] not in CLASSIFICATION_VALID_VALUES:
            raise INVALID_VALUE_TYPE("Value must be one of the following: %s"
                                     % ', '.join(CLASSIFICATION_VALID_VALUES))
        data = {'classification': kwargs['classification'],
                'query': kwargs['query']}
        return self._send_data('POST', ACTIONS, ACTIONS_CLASSIFICATION, data)

    def get_tags(self, **kwargs):
        return self._get(ACTIONS, ACTIONS_TAG, **kwargs)

    def add_tags(self, **kwargs):
        if type(kwargs['tags']) == str:
            kwargs['tags'] = [x.strip() for x in kwargs['tags'].split(',')]
        if type(kwargs['tags']) != list:
            raise INVALID_VALUE_TYPE("Tags must be a list.")
        data = {'tags': list(set(kwargs['tags'])), 'query': kwargs['query']}
        return self._send_data('PUT', ACTIONS, ACTIONS_TAG, data)

    def remove_tags(self, **kwargs):
        if type(kwargs['tags']) == str:
            kwargs['tags'] = [x.strip() for x in kwargs['tags'].split(',')]
        if type(kwargs['tags']) != list:
            raise INVALID_VALUE_TYPE("Tags must be a list.")
        data = {'tags': list(set(kwargs['tags'])), 'query': kwargs['query']}
        return self._send_data('DELETE', ACTIONS, ACTIONS_TAG, data)

    def set_tags(self, **kwargs):
        if type(kwargs['tags']) == str:
            kwargs['tags'] = [x.strip() for x in kwargs['tags'].split(',')]
        if type(kwargs['tags']) != list:
            raise INVALID_VALUE_TYPE("Tags must be a list.")
        data = {'tags': list(set(kwargs['tags'])), 'query': kwargs['query']}
        return self._send_data('POST', ACTIONS, ACTIONS_TAG, data)

    def get_metadata(self, **kwargs):
        return self._get(ENRICHMENT, '', **kwargs)
