"""
Sychronize local and remote resources.

To implement a new service, see the _SyncServiceInterface class.
"""

import abc
import copy

import requests
import threddsclient


def merge_local_and_remote_resources(resources_local, service_name, service_url):
    """Main function to sync resources with remote server"""
    if service_url.endswith("/"):  # remove trailing slash
        service_url = service_url[:-1]

    synchronizers = {
        "thredds": _SyncServiceThreads(service_url),
        "geoserver-api": _SyncServiceGeoserver(service_url),
    }

    sync_service = synchronizers.get(service_name.lower(), _SyncServiceDefault())

    remote_resources = sync_service.get_resources()
    merged_resources = _merge_resources(resources_local, remote_resources)

    return merged_resources


def _merge_resources(resources_local, resources_remote):
    """
    Merge resources_local and resources_remote, adding the following keys to the output:

        - remote_path: '/' separated string representing the remote path of the resource
        - matches_remote: True or False depending if the resource is present on the remote server
        - id: set to the value of 'remote_path' if the resource if remote only

    returns a dictionary of the form validated by 'is_valid_resource_schema'

    """
    if not resources_remote:
        return resources_local

    assert _is_valid_resource_schema(resources_local)
    assert _is_valid_resource_schema(resources_remote)

    if not resources_local:
        raise ValueError("The resources must contain at least the service name.")

    # The first item is the service name. It is skipped so that only the resources are compared.
    service_name = resources_local.keys()[0]
    _, remote_values = resources_remote.popitem()
    resources_remote = {service_name: remote_values}

    # don't overwrite the input arguments
    merged_resources = copy.deepcopy(resources_local)

    def recurse(_resources_local, _resources_remote, remote_path=""):
        for resource_name_local, values in _resources_local.items():
            current_path = "/".join([remote_path, resource_name_local])
            matches_remote = resource_name_local in _resources_remote

            values["remote_path"] = current_path
            values["matches_remote"] = matches_remote

            resource_remote_children = _resources_remote[resource_name_local]['children'] if matches_remote else {}

            recurse(values['children'], resource_remote_children, current_path)

        for resource_name_remote, values in _resources_remote.items():
            if resource_name_remote not in _resources_local:
                current_path = "/".join([remote_path, resource_name_remote])
                new_resource = {'permission_names': [],
                                'children': {},
                                'id': current_path,
                                'remote_path': current_path,
                                'matches_remote': True}

                _resources_local[resource_name_remote] = new_resource
                recurse(new_resource['children'], values['children'], current_path)

    recurse(merged_resources, resources_remote)

    return merged_resources


def _is_valid_resource_schema(resources):
    """
    Returns True if the structure of the input dictionary is a tree of the form:

    {'resource_name_1': {'children': {'resource_name_3': {'children': {}},
                                      'resource_name_4': {'children': {}}
                                      }
                         },
     'resource_name_2': {'children': {}}
     }
    :return: bool
    """
    for resource_name, values in resources.items():
        if not isinstance(resource_name, basestring):
            return False
        if 'children' not in values:
            return False
        if not isinstance(values['children'], dict):
            return False
        return _is_valid_resource_schema(values['children'])
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


class _SyncServiceGeoserver:
    def __init__(self, geoserver_url):
        self.geoserver_url = geoserver_url

    def get_resources(self):
        # Only workspaces are fetched for now
        workspaces_url = "{}/{}".format(self.geoserver_url, "workspaces")
        resp = requests.get(workspaces_url, headers={"Accept": "application/json"})
        resp.raise_for_status()
        workspaces_list = resp.json().get("workspaces", {}).get("workspace", {})

        workspaces = {w["name"]: {"children": {}} for w in workspaces_list}

        resources = {"geoserver-api": {"children": workspaces}}
        assert _is_valid_resource_schema(resources), "Error in Interface implementation"
        return resources


class _SyncServiceThreads(_SyncServiceInterface):
    DEPTH_DEFAULT = 2

    def __init__(self, thredds_url, depth=DEPTH_DEFAULT, **kwargs):
        self.thredds_url = thredds_url
        self.depth = depth
        self.kwargs = kwargs  # kwargs is passed to the requests.get method.

    def get_resources(self):
        def thredds_get_resources(url, depth, **kwargs):
            cat = threddsclient.read_url(url, **kwargs)
            name = cat.name

            tree_item = {name: {'children': {}}}

            if depth > 0:
                for reference in cat.flat_references():
                    tree_item[name]['children'].update(thredds_get_resources(reference.url, depth - 1, **kwargs))

            return tree_item

        resources = thredds_get_resources(self.thredds_url, self.depth, **self.kwargs)
        assert _is_valid_resource_schema(resources), "Error in Interface implementation"
        return resources


class _SyncServiceDefault(_SyncServiceInterface):
    def get_resources(self):
        return {}
