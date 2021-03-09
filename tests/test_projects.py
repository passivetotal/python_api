from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.projects import ProjectsRequest


class ProjectsTestCase(unittest.TestCase):

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = ProjectsRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()
    
    def test_get_projects(self):
        response = self.client.get_projects()
        assert('results' in response)
        assert(response['results'][0]['guid'] == "4baf9154f3cf")
        assert(type(response['results'][0]['subscribers']) == list)
    