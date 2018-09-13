"""
Sychronize local and remote resources.

To implement a new service, see the _SyncServiceInterface class.
"""

import abc
import copy
import datetime
from collections import OrderedDict

import requests
import threddsclient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from magpie import db, models


def merge_local_and_remote_resources(resources_local, service_name, session):
    """Main function to sync resources with remote server"""
    remote_resources = _query_resources(service_name, session=session)
    merged_resources = _merge_resources(resources_local, remote_resources)
    _sort_resources(merged_resources)
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

    assert _is_valid_resource_schema(resources_local, ignore_resource_type=True)
    assert _is_valid_resource_schema(resources_remote)

    if not resources_local:
        raise ValueError("The resources must contain at least the service name.")

    # The first item is the service name. It is skipped so that only the resources are compared.
    service_name = resources_local.keys()[0]
    _, remote_values = resources_remote.popitem()
    resources_remote = {service_name: remote_values}

    # don't overwrite the input arguments
    merged_resources = copy.deepcopy(resources_local)

    def recurse(_resources_local, _resources_remote, remote_path="", remote_type_path=""):
        # loop local resources, looking for matches in remote resources
        for resource_name_local, values in _resources_local.items():
            current_path = "/".join([remote_path, str(resource_name_local)])

            matches_remote = resource_name_local in _resources_remote
            resource_type = _resources_remote[resource_name_local]['resource_type'] if matches_remote else ""
            current_type_path = "/".join([remote_type_path, resource_type])

            values["remote_path"] = "" if matches_remote else current_path
            values["remote_type_path"] = current_type_path
            values["matches_remote"] = matches_remote
            values["resource_type"] = resource_type

            resource_remote_children = _resources_remote[resource_name_local]['children'] if matches_remote else {}

            recurse(values['children'], resource_remote_children, current_path, current_type_path)

        # loop remote resources, looking for matches in local resources
        for resource_name_remote, values in _resources_remote.items():
            if resource_name_remote not in _resources_local:
                current_path = "/".join([remote_path, str(resource_name_remote)])
                current_type_path = "/".join([remote_type_path, values['resource_type']])
                new_resource = {'permission_names': [],
                                'children': {},
                                'resource_type': values['resource_type'],
                                'id': current_path,
                                'remote_path': current_path,
                                'remote_type_path': current_type_path,
                                'matches_remote': True}
                _resources_local[resource_name_remote] = new_resource
                recurse(new_resource['children'], values['children'], current_path, current_type_path)

    recurse(merged_resources, resources_remote)

    assert _is_valid_resource_schema(merged_resources)

    return merged_resources


def _is_valid_resource_schema(resources, ignore_resource_type=False):
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
        return _is_valid_resource_schema(values['children'],
                                         ignore_resource_type=ignore_resource_type)
    return True


def _sort_resources(resources):
    """
    Sorts a resource dictionary of the type validated by '_is_valid_resource_schema'
    by using an OrderedDict
    :return: None
    """
    for resource_name, values in resources.items():
        values['children'] = OrderedDict(sorted(values['children'].iteritems()))
        return _sort_resources(values['children'])


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
        resource_type = "route"
        workspaces_url = "{}/{}".format(self.geoserver_url, "workspaces")
        resp = requests.get(workspaces_url, headers={"Accept": "application/json"})
        resp.raise_for_status()
        workspaces_list = resp.json().get("workspaces", {}).get("workspace", {})

        workspaces = {w["name"]: {"children": {}, "resource_type": resource_type} for w in workspaces_list}

        resources = {"geoserver-api": {"children": workspaces,
                                       "resource_type": resource_type}}
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
            resource_type = 'directory'
            if cat.datasets and cat.datasets[0].content_type != "application/directory":
                resource_type = 'file'

            tree_item = {name: {'children': {}, 'resource_type': resource_type}}

            if depth > 0:
                for reference in cat.flat_references():
                    tree_item[name]['children'].update(thredds_get_resources(reference.url, depth - 1, **kwargs))

            return tree_item

        resources = thredds_get_resources(self.thredds_url, self.depth, **self.kwargs)
        assert _is_valid_resource_schema(resources), 'Error in Interface implementation'
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


def _ensure_sync_info_exists(service_name, session):
    """
    Make sure the RemoteResourcesSyncInfo entry exists in the database.
    :param service_name:
    :param session:
    """
    service = models.Service.by_service_name(service_name, db_session=session)
    service_sync_info = models.RemoteResourcesSyncInfo.by_service_id(service.resource_id, session)
    if not service_sync_info:
        sync_info = models.RemoteResourcesSyncInfo(service_id=service.resource_id)
        session.add(sync_info)
        session.flush()
        _create_main_resource(service.resource_id, session)


def _get_remote_resources(service, service_name):
    """
    Request rmeote resources, depending on service type.
    :param service:
    :param service_name:
    :return:
    """
    service_url = service.url
    if service_url.endswith("/"):  # remove trailing slash
        service_url = service_url[:-1]
    sync_service = SYNC_SERVICES.get(service_name.lower(), _SyncServiceDefault)(service_url)
    return sync_service.get_resources()


def _delete_records(service_id, session):
    """
    Delete all RemoteResource based on a Service.resource_id
    :param service_id:
    :param session:
    """
    session.query(models.RemoteResource).filter_by(service_id=service_id).delete()
    session.flush()


def _create_main_resource(service_id, session):
    """
    Creates a main resource for a service, whether one currently exists or not.

    Each RemoteResourcesSyncInfo has a main RemoteResource of the same name as the service.
    This is similar to the Service and Resource relationship.
    :param service_id:
    :param session:
    """
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_id, session)
    main_resource = models.RemoteResource(service_id=service_id,
                                          resource_name=unicode(sync_info.service.resource_name),
                                          resource_type=u"directory")
    session.add(main_resource)
    session.flush()
    sync_info.remote_resource_id = main_resource.resource_id
    session.flush()


def _update_db(remote_resources, service_id, session):
    """
    Writes remote resources to database.
    :param remote_resources:
    :param service_id:
    :param session:
    """
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_id, session)

    def add_children(resources, parent_id, position=0):
        for resource_name, values in resources.items():
            new_resource = models.RemoteResource(service_id=sync_info.service_id,
                                                 resource_name=unicode(resource_name),
                                                 resource_type=values['resource_type'],
                                                 parent_id=parent_id,
                                                 ordering=position)
            session.add(new_resource)
            session.flush()
            position += 1
            add_children(values['children'], new_resource.resource_id)

    first_item = list(remote_resources)[0]
    add_children(remote_resources[first_item]['children'], sync_info.remote_resource_id)

    sync_info.last_sync = datetime.datetime.now()

    session.flush()


def _get_resource_children(resource, db_session):
    """
    Mostly copied from ziggurat_foundations to use RemoteResource instead of Resource
    :param resource:
    :param db_session:
    :return:
    """
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

    return build_subtree_strut(query)['children']


def _query_resources(service_name, session):
    """
    Reads remote resources from database. No external request is made.
    :param service_name:
    :param session:
    :return: a dictionary of the form defined in '_is_valid_resource_schema'
    """
    service = models.Service.by_service_name(service_name, db_session=session)
    _ensure_sync_info_exists(service_name, session)

    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service.resource_id, session)
    main_resource = session.query(models.RemoteResource).filter_by(
        resource_id=sync_info.remote_resource_id).first()
    tree = _get_resource_children(main_resource, session)

    def _format_resource_tree(children):
        fmt_res_tree = {}
        for child_id, child_dict in children.items():
            resource = child_dict[u'node']
            new_children = child_dict[u'children']
            resource_dict = {'children': _format_resource_tree(new_children),
                             'resource_type': resource.resource_type}
            fmt_res_tree[resource.resource_name] = resource_dict
        return fmt_res_tree

    remote_resources = _format_resource_tree(tree)
    return {service_name: {'children': remote_resources, 'resource_type': 'directory'}}


def get_last_sync(service_name, session):
    last_sync = None
    service = models.Service.by_service_name(service_name, db_session=session)
    _ensure_sync_info_exists(service_name, session)
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service.resource_id, session)
    if sync_info:
        last_sync = sync_info.last_sync
    return last_sync


def fetch_single_service(service_name, session):
    """
    Get remote resources for a single service.
    :param service_name:
    :param session:
    """
    service = models.Service.by_service_name(service_name, db_session=session)
    remote_resources = _get_remote_resources(service, service_name)
    service_id = service.resource_id
    _delete_records(service_id, session)
    _ensure_sync_info_exists(service_name, session)
    _update_db(remote_resources, service_id, session)


def fetch():
    """
    Main entry point to get all remote resources for each service and write to database.
    """
    url = db.get_db_url()
    engine = create_engine(url)

    session = Session(bind=engine)

    for service_name in SYNC_SERVICES:
        fetch_single_service(service_name, session)

    session.commit()
    session.close()


if __name__ == '__main__':
    fetch()
