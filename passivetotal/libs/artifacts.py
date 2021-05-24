"""PassiveTotal API Interface."""

from passivetotal.api import Client
from passivetotal.response import Response


class ArtifactsRequest(Client):

    """Client to interface with the Artifacts API calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(ArtifactsRequest, self).__init__(*args, **kwargs)

    def get_artifacts(self, **kwargs):
        """Get existing artifacts.

        Reference: https://api.passivetotal.org/index.html#api-Artifact-GetV2Artifact

        :param artifact: filter artifact ID, optional
        :param project: filter by project ID, optional
        :param owner: filter by owner (email or org id), optional
        :param creator: filter by creator, optional
        :param organization: filter by organization, optional
        :param query: filter by query, optional
        :param type: filter by artifact type, optional
        :return: Dict of results
        """
        return self._get('artifact', '', **kwargs)

    def create_artifact(self, project_guid, artifact, **kwargs):
        """Create a new artifact on an existing project.

        Reference: https://api.passivetotal.org/index.html#api-Artifact-PutV2Artifact

        :param project_guid: Project ID the artifact will be attached to
        :param artifact: The artifact itself - domain, IP, etc.
        :param type: type of the artifact or inferred automatically if not provided, optional
        :param tags: list of tags to label the new artifact with, optional
        :return: Dict of results
        """
        data = {
            'project': project_guid,
            'query': artifact,
        }
        data.update(kwargs)
        return self._send_data('PUT', 'artifact', '', data)
    
    def create_artifact_bulk(self, artifacts, **kwargs):
        """Create a bulk set of artifacts on an existing project.

        Reference: https://api.passivetotal.org/index.html#api-Artifact-PutV2ArtifactBulk

        :param artifacts: Array of artifact dictionaries with query, project guid, type, tags
        :return: Dict of results
        """
        data = {
            'artifacts': artifacts,
        }
        data.update(kwargs)
        return self._send_data('PUT', 'artifact', 'bulk', data)
    
    def upsert_artifact(self, project_guid, artifact, artifact_type=None, tags=None, monitor=None):
        """Update a matching artifact or create it if it does not exist.

        :param project_guid: Unique ID of the project containing the artifact
        :param artifact: String of the artifact
        :param type: Type of the artifact, optional (will be inferred if none provided)
        :param monitor: Whether to monitor the artifact (true or false), optional
        """
        results = self.get_artifacts(project=project_guid, query=artifact, type=artifact_type)
        if 'artifacts' in results: # API returned a list of more than one result
            raise Exception('More than one artifact matched your search.')
        if 'guid' in results: # API found one result
            artifact = results
        else: # API found no results
            artifact = self.create_artifact(project_guid=project_guid, artifact=artifact, type=artifact_type, tags=None)
        if tags is not None or monitor is not None:
            artifact = self.update_artifact(artifact['guid'], monitor=monitor, tags=tags)
        return artifact

    def update_artifact(self, artifact_guid, **kwargs):
        """Update an existing artifact.

        Reference: https://api.passivetotal.org/index.html#api-Artifact-PostV2Artifact

        :param artifact_guid: Artifact ID to update
        :param monitor: Whether to monitor the artifact (true or false), optional
        :param tags: list of tags to label the new artifact with, optional
        :return: Dict of results
        """
        data = {
            'artifact': artifact_guid,
        }
        data.update(kwargs)
        return self._send_data('POST', 'artifact', '', data)
    
    def update_artifact_bulk(self, artifacts, **kwargs):
        """Update a bulk set of artifacts on an existing project.

        Reference: https://api.passivetotal.org/index.html#api-Artifact-PostV2ArtifactBulk

        :param artifacts: Array of artifact dictionaries with artifact guid, monitor, tags
        :return: Dict of results
        """
        data = {
            'artifacts': artifacts,
        }
        data.update(kwargs)
        return self._send_data('POST', 'artifact', 'bulk', data)
    
    def delete_artifact(self, artifact_guid):
        """Delete an existing artifact.

        Reference: https://api.passivetotal.org/index.html#api-Artifact-DeleteV2Artifact

        :param artifact_guid: Artifact ID to delete
        :return: Dict of results
        """
        data = {
            'artifact': artifact_guid,
        }
        return self._send_data('DELETE', 'artifact', '', data)

class ArtifactsResponse(Response):
    pass