#!/usr/bin/env python
"""PassiveTotal API Interface."""

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

import json
import sys
import requests
from passivetotal.config import Config

py_v2 = (sys.version_info[0] == 2)
py_v3 = (sys.version_info[0] == 3)
if py_v2:
    import httplib

# import logging
# logging.basicConfig(level=logging.DEBUG)


class Client(object):

    """Base client that all data sources will inherit from."""

    DEFAULT_SERVER = 'api.passivetotal.org'
    DEFAULT_VERSION = 'v2'
    TIMEOUT = 30

    def __init__(self, username, api_key, server=DEFAULT_SERVER,
                 version=DEFAULT_VERSION, http_proxy=None, https_proxy=None):
        """Initial loading of the client.

        :param str api_key: API key from PassiveTotal.org
        :param str server: Hostname for the API
        :param str version: Version of the API to use
        :param str http_proxy: HTTP proxy to use (optional)
        :param str https_proxy: HTTPS proxy to use (optional)
        """
        self.api_base = 'https://%s/%s' % (server, version)
        self.username = username
        self.api_key = api_key
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        self.proxies = {}
        if http_proxy:
            self.proxies['http'] = http_proxy
        if https_proxy:
            self.proxies['https'] = https_proxy

    @classmethod
    def from_config(cls):
        """Method to return back a loaded instance."""
        config = Config()
        client = cls(
            username=config.get('username'),
            api_key=config.get('api_key'),
            server=config.get('api_server'),
            version=config.get('api_version'),
            http_proxy=config.get('http_proxy'),
            https_proxy=config.get('https_proxy'),
        )
        return client

    def _endpoint(self, endpoint, action, *url_args):
        """Return the URL for the action.

        :param str endpoint: The controller
        :param str action: The action provided by the controller
        :param url_args: Additional endpoints(for endpoints that take part of
                         the url as option)
        :return: Full URL for the requested action
        """
        args = (self.api_base, endpoint, action)
        if action == '':
            args = (self.api_base, endpoint)
        api_url = "/".join(args)
        if url_args:
            if len(url_args) == 1:
                api_url += "/" + url_args[0]
            else:
                api_url += "/".join(url_args)
        return api_url

    def _dump_requests(self):
        """Dump requests being made."""
        self._old_send = httplib.HTTPConnection.send
        old_send = self._old_send

        def new_send(self, data):
            print(data)
            return old_send(self, data)

        httplib.HTTPConnection.send = new_send

    def _undump_requests(self):
        """Reload request details."""
        httplib.HTTPConnection.send = self._old_send

    def _json(self, response):
        """JSON response from server.

        :param response: Response from the server
        :throws ValueError: from requests' response.json() error
        :return: response deserialized from JSON
        """
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as e:
            raise ValueError(
                'Exception: %s\n'
                'request: %s, response code: %s, response: %s' % (
                    str(e), response.request.url, response.status_code,
                    response.content,
                )
            )

    def _get(self, endpoint, action, *url_args, **url_params):
        """Request API Endpoint - for GET methods.

        :param str endpoint: Endpoint
        :param str action: Endpoint Action
        :param url_args: Additional endpoints(for endpoints that take part of
                         the url as option)
        :param url_params: Parameters to pass to url, typically query string
        :return: response deserialized from JSON
        """
        api_url = self._endpoint(endpoint, action, *url_args)
        # if 'timeout' in url_params:
        #     timeout = url_params['timeout']
        #     del url_params['timeout']
        # else:
        #     timeout = Client.TIMEOUT
        url_params.update({'api_key': self.api_key})
        kwargs = {'headers': self.headers, 'params': url_params,
                  'timeout': Client.TIMEOUT, 'verify': False,
                  'auth': (self.username, self.api_key)}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        response = requests.get(api_url, **kwargs)
        return self._json(response)

    def _send_data(self, method, endpoint, action,
                   data, *url_args, **url_params):
        """Submit to API Endpoint - for DELETE, PUT, POST methods.

        :param str method: Method to use for the request
        :param str endpoint: Endpoint
        :param str action: Endpoint Action
        :param url_args: Additional endpoints(for endpoints that take part of
                         the url as option)
        :param url_params: Parameters to pass to url, typically query string
        :return: response deserialized from JSON
        """
        api_url = self._endpoint(endpoint, action, *url_args)
        data.update({'api_key': self.api_key})
        data = json.dumps(data)
        kwargs = {'headers': self.headers, 'params': url_params,
                  'verify': True, 'data': data,
                  'auth': (self.username, self.api_key)}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        response = requests.request(method, api_url, **kwargs)
        return self._json(response)