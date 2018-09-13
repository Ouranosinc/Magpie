"""
Sychronize local and remote resources.

To implement a new service, see the _SyncServiceInterface class.
"""

import abc
import copy
from collections import OrderedDict

import requests
import threddsclient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from magpie import db, models


def merge_local_and_remote_resources(resources_local, service_name, session):
    """Main function to sync resources with remote server"""
    remote_resources = query_resources(service_name, session=session)
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
        # loop local resources, looking for matches in remote resources
        for resource_name_local, values in _resources_local.items():
            current_path = "/".join([remote_path, str(resource_name_local)])
            matches_remote = resource_name_local in _resources_remote

            values["remote_path"] = "" if matches_remote else current_path
            values["matches_remote"] = matches_remote

            resource_remote_children = _resources_remote[resource_name_local]['children'] if matches_remote else {}

            recurse(values['children'], resource_remote_children, current_path)

        # loop remote resources, looking for matches in local resources
        for resource_name_remote, values in _resources_remote.items():
            if resource_name_remote not in _resources_local:
                current_path = "/".join([remote_path, str(resource_name_remote)])
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
    def __init__(self, _):
        pass

    def get_resources(self):
        return {}


SYNC_SERVICES = {
    "thredds": _SyncServiceThreads,
    "geoserver-api": _SyncServiceGeoserver,
}


def _resource_tree_parser(resources, permissions):
    resources_tree = {}
    for r_id, resource in resources.items():
        children = _resource_tree_parser(resource['children'], permissions)
        resources_tree[resource['resource_name']] = dict(id=r_id, permission_names=permissions, children=children)
    return resources_tree


def get_resource_children(resource, db_session):
    query = models.remote_resource_tree_service.from_parent_deeper(resource.resource_id, db_session=db_session)

    def build_subtree_strut(result):
        """
        Returns a dictionary in form of
        {node:Resource, children:{node_id: RemoteResource}}
        """
        items = list(result)
        root_elem = {'node': None, 'children': OrderedDict()}
        if len(items) == 0:
            return root_elem
        for i, node in enumerate(items):
            new_elem = {'node': node.RemoteResource, 'children': OrderedDict()}
            path = list(map(int, node.path.split('/')))
            parent_node = root_elem
            normalized_path = path[:-1]
            if normalized_path:
                for path_part in normalized_path:
                    parent_node = parent_node['children'][path_part]
            parent_node['children'][new_elem['node'].resource_id] = new_elem
        return root_elem

    return build_subtree_strut(query)[u'children']


def ensure_sync_info_exists(service_name, session):
    service = models.Service.by_service_name(service_name, db_session=session)
    service_sync_info = models.RemoteResourcesSyncInfo.by_service_id(service.resource_id, session)
    if not service_sync_info:
        sync_info = models.RemoteResourcesSyncInfo(service_id=service.resource_id)
        session.add(sync_info)
        session.flush()
        create_main_resource(service.resource_id, session)


def get_remote_resources(service, service_name):
    service_url = service.url
    if service_url.endswith("/"):  # remove trailing slash
        service_url = service_url[:-1]
    sync_service = SYNC_SERVICES.get(service_name.lower(), _SyncServiceDefault)(service_url)
    return sync_service.get_resources()


def delete_records(service_id, session):
    session.query(models.RemoteResource).filter_by(service_id=service_id).delete()
    session.flush()


def create_main_resource(service_id, session):
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_id, session)
    main_resource = models.RemoteResource(service_id=service_id,
                                          resource_name=unicode(sync_info.service.resource_name),
                                          resource_type=u"directory")
    session.add(main_resource)
    session.flush()
    sync_info.remote_resource_id = main_resource.resource_id
    session.flush()


def update_db(remote_resources, service_id, session):
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_id, session)

    def add_children(resources, parent_id, position=0):
        for resource_name, values in resources.items():
            new_resource = models.RemoteResource(service_id=sync_info.service_id,
                                                 resource_name=unicode(resource_name),
                                                 resource_type=u"directory",  # todo: fixme
                                                 parent_id=parent_id,
                                                 ordering=position)
            session.add(new_resource)
            session.flush()
            position += 1
            add_children(values['children'], new_resource.resource_id)

    first_item = list(remote_resources)[0]
    add_children(remote_resources[first_item]['children'], sync_info.remote_resource_id)

    session.flush()


def fetch():
    url = db.get_db_url()
    engine = create_engine(url)

    session = Session(bind=engine)

    for service_name in SYNC_SERVICES:
        service = models.Service.by_service_name(service_name, db_session=session)

        remote_resources = get_remote_resources(service, service_name)

        service_id = service.resource_id

        delete_records(service_id, session)

        ensure_sync_info_exists(service_name, session)

        update_db(remote_resources, service_id, session)

    session.commit()
    session.close()


def format_resource_tree(children):
    fmt_res_tree = {}
    for child_id, child_dict in children.items():
        resource = child_dict[u'node']
        new_children = child_dict[u'children']
        fmt_res_tree[resource.resource_name] = {}
        fmt_res_tree[resource.resource_name][u'children'] = format_resource_tree(new_children)

    return fmt_res_tree


def query_resources(service_name, session):
    service = models.Service.by_service_name(service_name, db_session=session)
    ensure_sync_info_exists(service_name, session)

    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service.resource_id, session)
    main_resource = session.query(models.RemoteResource).filter_by(
        resource_id=sync_info.remote_resource_id).first()
    tree = get_resource_children(main_resource, session)
    remote_resources = format_resource_tree(tree)
    return {service_name: {'children': remote_resources}}


if __name__ == '__main__':
    fetch()
