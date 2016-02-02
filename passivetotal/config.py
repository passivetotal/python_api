#!/usr/bin/env python
__author__ = 'Brandon Dixon (PassiveTotal)'
__version__ = '1.0.0'

import json
import os
import sys

CONFIG_PATH = os.path.expanduser('~/.config/passivetotal')
CONFIG_FILE = os.path.join(CONFIG_PATH, 'api_config.json')
CONFIG_DEFAULTS = {
    'api_server': 'api.passivetotal.org',
    'api_version': 'v2',
    'api_key': '',
    'username': ''
}


class Config(object):

    """Manage configuration to ease library use."""

    def __init__(self, **kwargs):
        """Initialize the class."""
        self.config = CONFIG_DEFAULTS
        try:
            self.load_config(**kwargs)
        except ValueError as e:
            sys.stderr.write('Error: {}\n'.format(e.message))
            sys.exit(1)

    def write_config(self):
        """Write the configuration to a local file.

        :return: Boolean if successful
        """
        json.dump(
            self.config,
            open(CONFIG_FILE, 'w'),
            indent=4,
            separators=(',', ': ')
        )
        return True

    def load_config(self, **kwargs):
        """Load the configuration for the user or seed it with defaults.

        :return: Boolean if successful
        """
        virgin_config = False
        if not os.path.exists(CONFIG_PATH):
            virgin_config = True
            os.makedirs(CONFIG_PATH)
        if not os.path.exists(CONFIG_FILE):
            virgin_config = True
        if not virgin_config:
            self.config = json.load(open(CONFIG_FILE))
        if kwargs:
            self.config.update(kwargs)
        if virgin_config or kwargs:
            self.write_config()
        if 'api_key' not in self.config:
            sys.stderr.write('configuration missing API key\n')
        if 'username' not in self.config:
            sys.stderr.write('configuration missing username\n')
        if not ('api_key' in self.config and 'username' in self.config):
            sys.stderr.write('Errors have been reported. Run pt-config '
                             'to fix these warnings.\n')
        return True

    @property
    def options(self):
        """Return configuration option data.

        :return: Dict of configuration keys
        """
        return self.config.keys()

    def get(self, item, default=None):
        """Get details from the configuration.

        :param str item: Key used for search
        :param default: Default value if search misses
        :return: Configuration value
        """
        return self.config.get(item, default)
