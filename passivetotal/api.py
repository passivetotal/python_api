"""PassiveTotal API Interface."""


import json
import logging
import requests
import sys
from urllib.parse import quote as urlquote
from passivetotal.config import Config
from passivetotal._version import VERSION

__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = VERSION



class Client(object):

    """Base client that all data sources will inherit from."""

    DEFAULT_SERVER = 'api.passivetotal.org'
    DEFAULT_VERSION = 'v2'
    TIMEOUT = 30

    def __init__(self, username, api_key, server=DEFAULT_SERVER,
                 version=DEFAULT_VERSION, http_proxy=None, https_proxy=None,
                 verify=True, headers=None, debug=False, exception_class=Exception,
                 session=None):
        """Initial loading of the client.

        :param str username: API username in email address format
        :param str api_key: API secret or key
        :param str server: Base hostname for the API, defaults to api.passivetotal.org
        :param str version: Version of the API to use, defaults to v2
        :param str http_proxy: HTTP proxy to use (optional)
        :param str https_proxy: HTTPS proxy to use (optional)
        :param bool verify: Whether to verify the SSL certificate, defaults to True
        :param dict headers: Additional HTTP headers to add to the request
        :param bool debug: Whether to activate debugging
        :param class exception_class: Class of exception to raise on non-200 API responses (optional, defaults to None)
        """
        self.logger = logging.getLogger('pt-base-request')
        self.logger.setLevel('INFO')
        shandler = logging.StreamHandler(sys.stdout)
        fmtr = logging.Formatter('\033[1;32m%(levelname)-5s %(module)s:%(funcName)s():%(lineno)d %(asctime)s\033[0m| %(message)s')
        shandler.setFormatter(fmtr)
        self.logger.addHandler(shandler)

        self.api_base = 'https://%s/%s' % (server, version)
        self.username = username
        self.api_key = api_key
        self.headers = {
            'Accept': 'application/json',
        }
        self.proxies = {}
        if http_proxy:
            self.proxies['http'] = http_proxy
        if https_proxy:
            self.proxies['https'] = https_proxy
        if headers:
            self.headers.update(headers)
        self.verify = verify
        if '127.0.0.1' in server:
            self.verify = False
        self.exception_class = exception_class
        self.set_context('python','passivetotal',VERSION)
        self.session = session or requests.Session()

    @classmethod
    def from_config(cls, **kwargs):
        """Method to return back a loaded instance.
        
        kwargs override configuration file variables if provided and are passed to the object constructor.
        """
        arg_keys = ['username','api_key','server','version','http_proxy','https_proxy']
        args = { k: kwargs.pop(k) if k in kwargs else None for k in arg_keys }
        config = Config()
        client = cls(
            username    = args.get('username') or config.get('username'),
            api_key     = args.get('api_key') or config.get('api_key'),
            server      = args.get('server') or config.get('api_server'),
            version     = args.get('version') or config.get('api_version'),
            http_proxy  = args.get('http_proxy') or config.get('http_proxy'),
            https_proxy = args.get('https_proxy') or config.get('https_proxy'),
            **kwargs
        )
        return client

    def set_debug(self, status):
        if status:
            self.logger.setLevel('DEBUG')
        else:
            self.logger.setLevel('INFO')
        
    def set_context(self, provider, variant, version, feature=''):
        """Set the context for this request.
        
        :param provider: The company, partner, provider or other top-level application context.
        :param variant: The specific app, libary subcomponent, or feature category.
        :param version: Version of the app, feature or code setting the context.
        :param feature: Optional sub-feature, dashboard or script name.
        """
        context = Context(provider, variant, version, feature)
        self.context = context
        self.headers.update(context.get_header())

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

    def _json(self, response):
        """JSON response from server.

        :param response: Response from the server
        :throws ValueError: from requests' response.json() error
        :return: response deserialized from JSON
        """
        if response.status_code == 204:
            return None
        if response.status_code != 200 and self.exception_class is not None:
            raise self.exception_class(response)
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
        kwargs = {'headers': self.headers, 'params': url_params,
                  'timeout': Client.TIMEOUT, 'verify': self.verify,
                  'auth': (self.username, self.api_key)}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        self.logger.debug("Requesting: %s, %s" % (api_url, str(kwargs)))
        response = self.session.get(api_url, **kwargs)
        return self._json(response)

    def _get_special(self, endpoint, action, trail, data, *url_args, **url_params):
        """Request API Endpoint - for GET methods.

        :param str endpoint: Endpoint
        :param str action: Endpoint Action
        :param url_args: Additional endpoints(for endpoints that take part of
                         the url as option)
        :param url_params: Parameters to pass to url, typically query string
        :return: response deserialized from JSON
        """
        api_url = "/".join([self.api_base, endpoint, action, trail])
        data = json.dumps(data)
        kwargs = {'headers': self.headers, 'params': url_params,
                  'verify': self.verify, 'data': data,
                  'auth': (self.username, self.api_key)}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        response = self.session.get(api_url, **kwargs)
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
        kwargs = {'headers': self.headers, 'params': url_params,
                  'verify': self.verify, 'json': data,
                  'auth': (self.username, self.api_key)}
        if self.proxies:
            kwargs['proxies'] = self.proxies
        response = self.session.request(method, api_url, **kwargs)
        return self._json(response)



class Context:

    """Integration context for a set of API requests."""

    HEADER_NAME = 'X-RISKIQ-CONTEXT'

    def __init__(self, provider, variant, version, feature = ''):
        """Build a new context header.
        
        :param provider: The company, partner, provider or other top-level application context.
        :param variant: The specific app, libary subcomponent, or feature category.
        :param version: Version of the app, feature or code setting the context.
        :param feature: Optional sub-feature, dashboard or script name.
        """
        self._fields = (provider, variant, version, feature)
    
    def get_header_name(self):
        return self.HEADER_NAME
    
    def get_header_value(self):
        return '/'.join(map(lambda f: urlquote(f, safe=''), self._fields))
    
    def get_header(self):
        return { self.get_header_name() : self.get_header_value() }