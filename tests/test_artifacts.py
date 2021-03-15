from unittest.mock import patch
import unittest

from .conf import fake_request
from passivetotal.libs.artifacts import ArtifactsRequest


class ArtifactsTestCase(unittest.TestCase):

    def setUp(self):
        self.patcher = patch('passivetotal.api.Client._get', fake_request)
        self.patcher.start()
        self.client = ArtifactsRequest('--No-User--', '--No-Key--')

    def tearDown(self):
        self.patcher.stop()
    
    def test_get_artifacts(self):
        response = self.client.get_artifacts()
        assert('artifacts' in response)
        assert(response['artifacts'][0]['guid'] == "3bb5-3ab01cd")
        assert(type(response['artifacts'][1]['system_tags']) == list)
    