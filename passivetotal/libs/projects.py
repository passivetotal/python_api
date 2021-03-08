"""PassiveTotal API Interface."""

from passivetotal.api import Client
from passivetotal.response import Response



class ProjectsRequest(Client):

    """Client to interface with the Projects API calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(ProjectsRequest, self).__init__(*args, **kwargs)

    def get_projects(self, **kwargs):
        """Get all projects with optional filters.

        Reference: https://api.passivetotal.org/index.html#api-Project-GetV2Project

        :param project: Project UUID, optional
        :param owner: filter by owner (email or org id), optional
        :param creator: filter by creator email, optional
        :param organization: filter by organization, optional
        :param visibility: filter by visiblity (public, private, or analyst), optional
        :param featured: filter by featured status (true or false), optional
        :return: Dict of results
        """
        return self._get('project', '', **kwargs)
    
    def create_project(self, name, visiblity='analyst', **kwargs):
        """Create a new project.

        Reference: https://api.passivetotal.org/index.html#api-Project-PutV2Project

        :param name: Project name
        :param visibility: allowed values 'public', 'private', or 'analyst'
        :param description: project description, optional
        :param featured: whether to feature the project (true or false), optional
        :param tags: sets the projects tags to a list, optional
        :return: Dict of new project
        """
        if visiblity not in ['public','private','analyst']:
            raise INVALID_VALUE_TYPE
        data = {
            'name': name,
            'visibility': visiblity
        }
        data.update(kwargs)
        return self._send_data('PUT', 'project', '', data)
    
    def update_project(self, guid, **kwargs):
        """Update an existing project.

        Reference: https://api.passivetotal.org/index.html#api-Project-PostV2Project

        :param guid: Project ID
        :param name: New project name, optional
        :param visibility: allowed values 'public', 'private', or 'analyst', optional
        :param description: project description, optional
        :param featured: whether to feature the project (true or false), optional
        :param tags: sets the projects tags to a list, optional
        :return: Dict of new project
        """
        data = {
            'project': guid,
        }
        data.update(kwargs)
        return self._send_data('POST', 'project', '', data)
    
    def delete_project(self, guid):
        """Delete an existing project.

        Reference: https://api.passivetotal.org/index.html#api-Project-DeleteV2Project

        :param guid: Project ID
        """
        data = {
            'project': guid,
        }
        return self._send_data('DELETE', 'project', '', data)

    def add_tags(self, project_guid, tags):
        """Add tags to an existing project.

        Reference: https://api.passivetotal.org/index.html#api-Project-PostV2ProjectTag

        :param project_guid: Project ID
        :param tags: List of tags to add
        """
        data = {
            'project': project_guid,
            'tags': tags
        }
        return self._send_data('POST', 'project', 'tag', data)
    
    def set_tags(self, project_guid, tags):
        """Set all tags on an existing project.

        Reference: https://api.passivetotal.org/index.html#api-Project-PutV2ProjectTag

        :param project_guid: Project ID
        :param tags: List of tags to set
        """
        data = {
            'project': project_guid,
            'tags': tags
        }
        return self._send_data('PUT', 'project', 'tag', data)
    
    def remove_tags(self, project_guid, tags):
        """Remove a list of tags from an existing project.

        Reference: https://api.passivetotal.org/index.html#api-Project-DeleteV2ProjectTag

        :param project_guid: Project ID
        :param tags: List of tags to remove
        """
        data = {
            'project': project_guid,
            'tags': tags
        }
        return self._send_data('DELETE', 'project', 'tag', data)



class ProjectsResponse(Response):
    pass