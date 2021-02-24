import json
import os.path

current_version = 'v2'


def fake_request(*args, **kwargs):
    """Fake a URL request by fetching results locally."""
    arguments = list(args)
    if type(arguments[-1]) == dict:
        arguments.pop()
        arguments.pop(0)
    # replace the class instance with our test version
    arguments[0] = current_version
    url_path = '/'.join(arguments)
    if arguments[-1] == '':
        url_path = url_path.rstrip('/')

    resource_file = os.path.normpath('tests/resources/%s.json' % url_path)
    with open(resource_file, mode='rb') as response:
        raw_data = response.read().decode('utf-8')
    return json.loads(raw_data)

