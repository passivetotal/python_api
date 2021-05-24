"""PassiveTotal API Interface."""

import re
from passivetotal.api import Client
from passivetotal.response import Response



class ProjectsRequest(Client):

    """Client to interface with the Projects API calls from the PassiveTotal API."""

    def __init__(self, *args, **kwargs):
        """Setup the primary client instance."""
        super(ProjectsRequest, self).__init__(*args, **kwargs)
    
    @classmethod
    def is_guid(cls, test):
        pattern = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
        return len(pattern.findall(test))==1
    
    def find_projects(self, name_or_guid, visibility='analyst', owner=None, creator=None, org=None):
        """Obtain a list of all projects and find any project that match the criteria.

        Set owner='me' or creator='me' to use the API username.

        :param name_or_guid: Project name or project guid
        :param visibility: Project visiblity: public, private, or analyst (default), optional
        :param owner: Project owner, optional
        :param creator: Project creater, optional
        :param org: Project owner, optional
        """
        if owner == 'me':
            owner = self.username
        if creator == 'me':
            creator = self.username
        params = { 
            'visibility': visibility,
            'owner': self.username if owner=='me' else owner,
            'creator': self.username if creator=='me' else creator,
            'organization': org
        }
        if self.is_guid(name_or_guid):
            guid = name_or_guid
            name = None
            params['guid'] = name_or_guid
        else:
            guid = None
            name = name_or_guid
        results = self.get_projects(**params)
        if 'results' not in results:          # because only one project matched
            results = {'results': [results]} # synthesize a list of results 
        if len(results['results'])==0:
            return []
        def test(project):
            if guid is None:
                return project['name']==name
            else:
                return project['guid']==guid
        return list(filter(test, results.get('results',[])))

    def get_projects(self, **kwargs):
        """Get all projects with optional filters.

        Reference: https://api.passivetotal.org/index.html#api-Project-GetV2Project

        IMPORTANT: If only one project matches the search, the API will return a
        single result instead of a list.

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