from datetime import datetime
from passivetotal.analyzer import get_api, get_config, get_object
from passivetotal.analyzer._common import RecordList, Record, AnalyzerError


class ProjectList(RecordList):
    """List of Projects with artifacts."""
    
    def _get_shallow_copy_fields(self):
        return []

    def _get_sortable_fields(self):
        pass

    def _get_dict_fields(self):
        return []
    
    @staticmethod
    def find(name_or_guid, visibility='analyst', owner=None, creator=None, org=None):
        """Obtain a list of all projects and find the one project that match the other criteria.

        Set owner='me' or creator='me' to use the API username.

        :param name_or_guid: Project name or project guid
        :param visibility: Project visiblity: public, private, or analyst (default), optional
        :param owner: Project owner, optional
        :param creator: Project creater, optional
        :param org: Project owner, optional
        """
        results = get_api('Projects').find_projects(name_or_guid, visibility, owner, creator, org)
        return ProjectList(results)

    def parse(self, api_response):
        """Parse an API response."""
        self._records = []
        for project in api_response:
            self._records.append(Project(project))



class Project(Record):

    """Project record with collection of artifacts."""

    _instances = {}

    def __new__(cls, api_response):
        guid = api_response['guid']
        self = cls._instances.get(guid)
        if self is None:
            self = cls._instances[guid] = object.__new__(Project)
            self._guid = api_response['guid']
            self._active = api_response['active']
            self._name = api_response['name']
            self._description = api_response['description']
            self._visiblity = api_response['visibility']
            self._featured = api_response['featured']
            self._tags = api_response['tags']
            self._owner = api_response['owner']
            self._creator = api_response['creator']
            self._created = api_response['created']
            self._organization = api_response['organization']
            self._collaborators = api_response['collaborators']
            self._link = api_response['link']
            self._links = api_response['links']
            self._subscribers = api_response['subscribers']
            self._can_edit = api_response['can_edit']
        return self

    def __str__(self):
        return self.name
    
    def __repr__(self):
        return "<Project {0.guid} '{0.name}'".format(self)

    def _get_dict_fields(self):
        return ['project_guid','name','description','visibility','is_featured',
                'tags','owner','creator','str:created','organization','link',
                'collaborators','links','subscribers','can_edit']
    
    def _api_get_artifacts(self):
        """Query the artifacts API to load a list of artifacts for this project."""
        self._artifacts = []
        result = get_api('Artifacts').get_artifacts(project=self.guid)
        if 'message' in result:
            return
        self._artifacts = ArtifactList(result)
        return self._artifacts
    
    @staticmethod
    def find(name_or_guid, visibility='analyst', owner=None, creator=None, org=None):
        """Find one project that matches the other criteria.

        Raises AnalyzerError if more than one project is found.

        Set owner='me' or creator='me' to use the API username.

        :param name_or_guid: Project name or project guid
        :param visibility: Project visiblity: public, private, or analyst (default), optional
        :param owner: Project owner, optional
        :param creator: Project creater, optional
        :param org: Project owner, optional
        """
        project = Project._instances.get(name_or_guid)
        if project is not None:
            return project
        results = get_api('Projects').find_projects(name_or_guid, visibility, owner, creator, org)
        if len(results) == 0:
            return None
        if len(results) > 1:
            raise AnalyzerError('More than one project matched the search criteria.')
        return Project(results[0])

    @property
    def artifacts(self):
        """List of artifacts in this project.

        :rtype: :class:`passivetotal.analyzer.projects.ArtifactList` 
        """
        if getattr(self, '_artifacts', None) is not None:
            return self._artifacts
        return self._api_get_artifacts()

    @property
    def guid(self):
        """Alias for project_guid; project's unique identifier."""
        return self._guid
    
    @property
    def project_guid(self):
        """Project unique identifier."""
        return self._guid
    
    @property
    def name(self):
        """Name of the project."""
        return self._name
    
    @property
    def description(self):
        """Description of the project."""
        return self._description
    
    @property
    def visibility(self):
        """Visiblity of the project."""
        return self._visiblity
    
    @property
    def is_featured(self):
        """Whether this is a featured project."""
        return self._featured
    
    @property
    def tags(self):
        """List of tags associated with this project."""
        return self._tags
    
    @property
    def owner(self):
        """Owner of the project."""
        return self._owner
    
    @property
    def creator(self):
        """User ID of the project creator."""
        return self._creator
    
    @property
    def created(self):
        """Date this project was created."""
        return datetime.fromisoformat(self._created)
    
    @property
    def organization(self):
        """Organization this project is connected to."""
        return self._organization
    
    @property
    def collaborators(self):
        """List of user IDs collaborating on this project."""
        return self._collaborators
    
    @property
    def link(self):
        """Project link."""
        return self._link
    
    @property
    def links(self):
        """Dictionary of various links to this project in the UI."""
        return self._links
    
    @property
    def subscribers(self):
        """List of users who receive notifcations about artifacts in this project."""
        return self._subscribers
    
    @property
    def can_edit(self):
        """Whether the project can be edited."""
        return self._can_edit
    


class ArtifactList(RecordList):

    """List of artifact entries."""

    def _get_shallow_copy_fields(self):
        return []

    def _get_sortable_fields(self):
        return []

    def _get_dict_fields(self):
        return []
    
    def parse(self, api_response):
        """Parse an API response."""
        self._records = []
        if 'message' in api_response: # none found
            return
        if 'guid' in api_response: # one record
            self._records.append(Artifact(api_response))
        else:
            self._records.extend([ Artifact(a) for a in api_response['artifacts']])



class Artifact(Record):

    """An artifact in a project."""

    _instances = {}

    def __new__(cls, api_response):
        guid = api_response['guid']
        self = cls._instances.get('guid')
        if self is None:
            self = cls._instances[guid] = object().__new__(Artifact)
            self._type = api_response.get('type')
            self._project_guid = api_response.get('project')
            self._artifact_guid = api_response.get('guid')
            self._monitor = api_response.get('monitor')
            self._monitorable = api_response.get('monitorable')
            self._organization = api_response.get('organization')
            self._links = api_response.get('links')
            self._owner = api_response.get('owner')
            self._query = api_response.get('query')
            self._creator = api_response.get('creator')
            self._created = api_response.get('created')
            self._tags_meta = api_response.get('tag_meta')
            self._tags_global = api_response.get('global_tags')
            self._tags_system = api_response.get('system_tags')
            self._tags_user = api_response.get('user_tags')
        return self

    def __str__(self):
        return self.name

    def __repr__(self):
        return "<Artifact {0.guid} '{0.name}'>".format(self)

    def _get_dict_fields(self):
        return ['type','project_guid','artifact_guid','is_monitored',
                'is_monitorable','organization','links','owner','name','creator',
                'tags_meta','tags_global','tags_system','tags_user','str:created']

    def delete(self):
        """Delete this artifact record.
        
        :rtype bool: Whether the deletion was successful.
        """
        result = get_api('Artifacts').delete_artifact(self.guid)
        if 'message' in result:
            raise AnalyzerError('Cannot delete artifact: {}'.format(result['message']))
        else:
            return True
    
    def enable_monitoring(self):
        """Activate monitoring on this artifact.

        :rtype bool: Whether monitoring was activated successfully.
        """
        if self.is_monitored:
            return True
        result = get_api('Artifacts').update_artifact(self.guid, monitor=True)
        if 'message' in result:
            raise AnalyzerError('Cannot set monitoring: {}'.format(result['message']))
        self._monitor = result['monitor']
        return self._monitor
    
    def disable_monitoring(self):
        """Deactivate monitoring on this artifact.

        :rtype bool: Whether monitoring was deactivated successfully.
        """
        if not self.is_monitored:
            return True
        result = get_api('Artifacts').update_artifact(self.guid, monitor=False)
        if 'message' in result:
            raise AnalyzerError('Cannot set monitoring: {}'.format(result['message']))
        self._monitor = result['monitor']
        return not self._monitor
    
    def update_tags(self, new_tags):
        """Set a new list of tags on this artifact.

        The new tag list will overwrite the existing tag list.
        :rtype bool: Whether tags were updated successfully.
        """
        if type(new_tags) is str:
            tags = new_tags.split(',')
        else:
            tags = new_tags
        result = get_api('Artifacts').update_artifact(self.guid, tags=tags)
        if 'message' in result:
            raise AnalyzerError('Cannot set tags: {}'.format(result['message']))
        self._tags_user = result['user_tags']
        return True
    
    @property
    def project(self):
        pass

    @property
    def type(self):
        """Type of the artifact (IP, domain, hash, etc.)"""
        return self._type
    
    @property
    def project_guid(self):
        """Unique ID of the project that contains this artifact."""
        return self._project_guid
    
    @property
    def artifact_guid(self):
        """Unique ID of the artifact."""
        return self._artifact_guid
    
    @property
    def guid(self):
        """Unique ID of the artifact; alias of artifact_guid."""
        return self.artifact_guid
    
    @property
    def is_monitored(self):
        """Whether the artifact is actively being monitored."""
        return self._monitor
    
    @property
    def is_monitorable(self):
        """Whether the artifact can be monitored."""
        return self._monitorable
    
    @property
    def organization(self):
        """Organization that owns the artifact record."""
        return self._organization
    
    @property
    def links(self):
        """Dictionary of various link types to get more details in the UI."""
        return self._links
    
    @property
    def owner(self):
        """User or organization that owns the artifact record."""
        return self._owner
    
    @property
    def name(self):
        """Name of the artifact (the actual ip, domain, hash, etc.)"""
        return self._query
    
    @property
    def creator(self):
        """User ID that created the artifact."""
        return self._creator
    
    @property
    def created(self):
        """Date the artifact was created."""
        return datetime.fromisoformat(self._created)
    
    @property
    def tags_meta(self):
        """Descriptive data about the tags on this artifact."""
        return self._tags_meta
    
    @property
    def tags_system(self):
        """List of system tags for this artifact."""
        return self._tags_system
    
    @property
    def tags_global(self):
        """List of global tags for this artifact."""
        return self._tags_global
    
    @property
    def tags_user(self):
        """List of user-defined tags for this artifact."""
        return self._tags_user
    
    @property
    def hostname(self):
        """Hostname object for this artifact, if artifact type is domain."""
        if self.type == 'domain':
            return  get_object(self.name)
        else:
            return None
    
    @property
    def ip(self):
        """IPAddress object for this artifact, if artifact type is IP."""
        if self.type == 'ip':
            return get_object(self.name)
        else:
            return None



class IsArtifact:
    """An object that can be an artifact in an Illuminate project."""

    def _api_get_projects(self):
        """Query the artifacts and projects API for projects that include this object."""
        projects = []
        for artifact in self.artifacts:
            projects.extend(get_api('Projects').find_projects(artifact.project_guid))
        self._projects = ProjectList(projects)
        return self._projects
        

    def _api_get_artifacts(self):
        """Query the artifacts API to find project artifacts that match this object."""
        response = get_api('Artifacts').get_artifacts(query=self.get_host_identifier())
        self._artifacts = ArtifactList(response)
        return self._artifacts

    @property
    def projects(self):
        """List of projects that reference this object as an artifact.
        
        :rtype: :class:`passivetotal.analyzer.projects.ProjectList` 
        """
        if getattr(self, '_projects', None) is not None:
            return self._projects
        return self._api_get_projects()
    
    @property
    def artifacts(self):
        """List of project artifacts that correspond with this object.
        
        :rtype: :class:`passivetotal.analyzer.projects.ArtifactList` 
        """
        if getattr(self, '_artifacts', None) is not None:
            return self._artifacts
        return self._api_get_artifacts()
    
    def save_to_project(self, artifact_tags=None):
        """Save this object to the active project as an artifact.

        Before saving the object, call `analyzer.set_project()` to set or create
        the active project.

        :param project_tags: List of tags to apply to the artifact, optional. """
        project_guid = get_config('project_guid')
        if project_guid is None:
            raise AnalyzerError('Project is not set; call analyzer.set_project() to get started.')
        get_api('Artifacts').upsert_artifact(project_guid, self.get_host_identifier(), tags=artifact_tags)
