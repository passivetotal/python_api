import argparse
import datetime
import json
import os
import socket


def is_ip(value):
    """Determine if a value is an IP address.

    :param str value: Value to check
    :return: Boolean status outling if the value is an IP address
    """
    try:
        socket.inet_aton(value)
        return True
    except socket.error:
        return False


def to_bool(string):
    """Transform a string to a boolean if possible.

    :param str string: String to try and convert
    :return: Converted boolean
    """
    positive = ("yes", "y", "true",  "t", "1")
    if str(string).lower() in positive:
        return True
    negative = ("no",  "n", "false", "f", "0", "0.0", "", "none", "[]", "{}")
    if str(string).lower() in negative:
        return False
    raise Exception('Invalid value for boolean conversion: ' + str(value))


def prune_args(**kwargs):
    """Remove any keyword arguments with blank default.

    :return: Dict of keyword arguments without null values
    """
    return dict((k, v) for k, v in kwargs.iteritems() if v)


def valid_date(input_date):
    """Validate input dates against a certain format.

    :param str input_date: Date value to check
    :return: Loaded date value
    """
    try:
        return datetime.strptime(input_date, "%Y-%m-%d")
    except ValueError:
        msg = "Not a valid date: '{0}'.".format(input_date)
        raise argparse.ArgumentTypeError(msg)


def fake_request(*args, **kwargs):
    """Fake a URL request by fetching results locally.

    This is a help function to be used with the patch module in order to
    simulate responses from the API. Generally, you would use this when you
    want to test a tool locally or don't have the internet. Simply placing
    the following above your code will ensure it runs.

    from mock import patch
    from passivetotal.common.utilities import fake_request
    patcher = patch('passivetotal.api.Client._get', fake_request)
    patcher.start()

    :return: Dict of JSON simulating an API call
    """
    arguments = list(args)
    if type(arguments[-1]) == dict:
        arguments.pop()
        arguments.pop(0)
    arguments[0] = 'v2'
    url_path = '/'.join(arguments)
    if arguments[-1] == '':
        url_path = url_path.rstrip('/')

    resource_file = os.path.normpath('tests/resources/%s.json' % url_path)
    response = open(resource_file, mode='rb')
    raw_data = response.read().decode('utf-8')
    return json.loads(raw_data)
