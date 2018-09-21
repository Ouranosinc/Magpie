import abc
from collections import OrderedDict

import requests
import threddsclient

THREDDS_DEPTH_DEFAULT = 3


def is_valid_resource_schema(resources, ignore_resource_type=False):
    """
    Returns True if the structure of the input dictionary is a tree of the form:

    {'resource_name_1': {'children': {'resource_name_3': {'children': {}, 'resource_type': ...},
                                      'resource_name_4': {'children': {}, 'resource_type': ...}
                                      },
                         'resource_type': ...
                         },
     'resource_name_2': {'children': {}, resource_type': ...}
     }
    :return: bool
    """
    for resource_name, values in resources.items():
        if 'children' not in values:
            return False
        if not ignore_resource_type and 'resource_type' not in values:
            return False
        if not isinstance(values['children'], (OrderedDict, dict)):
            return False
        return is_valid_resource_schema(values['children'],
                                        ignore_resource_type=ignore_resource_type)
    return True


class _SyncServiceInterface:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_resources(self):
        """
        This is the function actually fetching the data from the remote service.
        Implement this for every specific service.

        :return: The returned dictionary must be validated by 'is_valid_resource_schema'
        """
        pass


class _SyncServiceGeoserver(_SyncServiceInterface):
    def __init__(self, service_name, geoserver_url):
        super(_SyncServiceGeoserver, self).__init__()
        self.service_name = service_name
        self.geoserver_url = geoserver_url

    def get_resources(self):
        # Only workspaces are fetched for now
        resource_type = "route"
        workspaces_url = "{}/{}".format(self.geoserver_url, "workspaces")
        resp = requests.get(workspaces_url, headers={"Accept": "application/json"})
        resp.raise_for_status()
        workspaces_list = resp.json().get("workspaces", {}).get("workspace", {})

        workspaces = {w["name"]: {"children": {}, "resource_type": resource_type} for w in workspaces_list}

        resources = {self.service_name: {"children": workspaces,
                                         "resource_type": resource_type}}
        assert is_valid_resource_schema(resources), "Error in Interface implementation"
        return resources


class _SyncServiceProjectAPI(_SyncServiceInterface):
    def __init__(self, service_name, project_api_url):
        super(_SyncServiceProjectAPI, self).__init__()
        self.service_name = service_name
        self.project_api_url = project_api_url

    def get_resources(self):
        # Only workspaces are fetched for now
        resource_type = "route"
        projects_url = "/".join([self.project_api_url, "api", "Projects"])
        resp = requests.get(projects_url)
        resp.raise_for_status()

        projects = {p["id"]: {"children": {}, "resource_type": resource_type} for p in resp.json()}

        resources = {self.service_name: {"children": projects, "resource_type": resource_type}}
        assert is_valid_resource_schema(resources), "Error in Interface implementation"
        return resources


class _SyncServiceThreads(_SyncServiceInterface):
    def __init__(self, service_name, thredds_url, depth=THREDDS_DEPTH_DEFAULT, **kwargs):
        super(_SyncServiceThreads, self).__init__()
        self.service_name = service_name
        self.thredds_url = thredds_url
        self.depth = depth
        self.kwargs = kwargs  # kwargs is passed to the requests.get method.

    def _resource_id(self, resource):
        id_ = resource.name
        if len(resource.datasets) > 0:
            id_ = resource.datasets[0].ID.split("/")[-1]
        return id_

    def get_resources(self):
        def thredds_get_resources(url, depth, **kwargs):
            cat = threddsclient.read_url(url, **kwargs)
            name = self._resource_id(cat)
            if depth == self.depth:
                name = self.service_name
            resource_type = 'directory'
            if cat.datasets and cat.datasets[0].content_type != "application/directory":
                resource_type = 'file'

            tree_item = {name: {'children': {}, 'resource_type': resource_type}}

            if depth > 0:
                for reference in cat.flat_references():
                    tree_item[name]['children'].update(thredds_get_resources(reference.url, depth - 1, **kwargs))

            return tree_item

        resources = thredds_get_resources(self.thredds_url, self.depth, **self.kwargs)
        assert is_valid_resource_schema(resources), 'Error in Interface implementation'
        return resources


class _SyncServiceDefault(_SyncServiceInterface):
    def __init__(self, *_):
        super(_SyncServiceDefault, self).__init__()
        pass

    def get_resources(self):
        return {}
