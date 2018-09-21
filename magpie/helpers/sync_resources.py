"""
Sychronize local and remote resources.

To implement a new service, see the _SyncServiceInterface class.
"""

import copy
import datetime
from collections import OrderedDict, defaultdict
import logging
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from magpie import db, models, constants
from magpie.helpers import sync_services
from magpie.helpers.sync_services import THREDDS_DEPTH_DEFAULT
from magpie.models import resource_tree_service

LOGGER = logging.getLogger(__name__)

CRON_SERVICE = False

OUT_OF_SYNC = datetime.timedelta(hours=3)

SYNC_SERVICES_TYPES = defaultdict(lambda: sync_services._SyncServiceDefault)
# noinspection PyTypeChecker
SYNC_SERVICES_TYPES.update({
    "thredds": sync_services._SyncServiceThreads,
    "geoserver-api": sync_services._SyncServiceGeoserver,
    "project-api": sync_services._SyncServiceProjectAPI,
})


def merge_local_and_remote_resources(resources_local, service_type, service_name, session):
    """Main function to sync resources with remote server"""
    if not get_last_sync(service_type, service_name, session):
        return resources_local
    remote_resources = _query_remote_resources_in_database(service_type, service_name, session=session)
    merged_resources = _merge_resources(resources_local, remote_resources)
    _sort_resources(merged_resources)
    return merged_resources


def _merge_resources(resources_local, resources_remote):
    """
    Merge resources_local and resources_remote, adding the following keys to the output:

        - remote_path: '/' separated string representing the remote path of the resource
        - matches_remote: True or False depending if the resource is present on the remote server
        - id: set to the value of 'remote_path' if the resource if remote only

    returns a dictionary of the form validated by 'sync_services.is_valid_resource_schema'

    """
    if not resources_remote:
        return resources_local

    assert sync_services.is_valid_resource_schema(resources_local, ignore_resource_type=True)
    assert sync_services.is_valid_resource_schema(resources_remote)

    if not resources_local:
        raise ValueError("The resources must contain at least the service name.")

    # don't overwrite the input arguments
    merged_resources = copy.deepcopy(resources_local)

    def recurse(_resources_local, _resources_remote, remote_path="", remote_type_path=""):
        # loop local resources, looking for matches in remote resources
        for resource_name_local, values in _resources_local.items():
            current_path = "/".join([remote_path, str(resource_name_local)])

            depth = current_path.count("/")
            deeper_than_fetched = depth >= THREDDS_DEPTH_DEFAULT

            matches_remote = resource_name_local in _resources_remote
            resource_type = _resources_remote[resource_name_local]['resource_type'] if matches_remote else ""
            current_type_path = "/".join([remote_type_path, resource_type])

            values["remote_path"] = current_path if matches_remote else ""
            values["remote_type_path"] = current_type_path if matches_remote else ""
            values["matches_remote"] = matches_remote or deeper_than_fetched
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

    assert sync_services.is_valid_resource_schema(merged_resources)

    return merged_resources


def _sort_resources(resources):
    """
    Sorts a resource dictionary of the type validated by 'sync_services.is_valid_resource_schema'
    by using an OrderedDict
    :return: None
    """
    for resource_name, values in resources.items():
        values['children'] = OrderedDict(sorted(values['children'].iteritems()))
        return _sort_resources(values['children'])


def _ensure_sync_info_exists(service_resource_id, session):
    """
    Make sure the RemoteResourcesSyncInfo entry exists in the database.
    :param service_resource_id:
    :param session:
    """
    service_sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_resource_id, session)
    if not service_sync_info:
        sync_info = models.RemoteResourcesSyncInfo(service_id=service_resource_id)
        session.add(sync_info)
        session.flush()
        _create_main_resource(service_resource_id, session)


def _get_remote_resources(service):
    """
    Request remote resources, depending on service type.
    :param service: (models.Service)
    :return:
    """
    service_url = service.url
    if service_url.endswith("/"):  # remove trailing slash
        service_url = service_url[:-1]

    sync_service_class = SYNC_SERVICES_TYPES.get(service.type.lower(), sync_services._SyncServiceDefault)
    sync_service = sync_service_class(service.resource_name, service_url)
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


def _format_resource_tree(children):
    fmt_res_tree = {}
    for child_id, child_dict in children.items():
        resource = child_dict[u'node']
        new_children = child_dict[u'children']
        resource_dict = {'children': _format_resource_tree(new_children),
                         'resource_type': resource.resource_type}
        fmt_res_tree[resource.resource_name] = resource_dict
    return fmt_res_tree


def _query_remote_resources_in_database(service_type, service_name, session):
    """
    Reads remote resources from the RemoteResources table. No external request is made.
    :param service_type:
    :param session:
    :return: a dictionary of the form defined in 'sync_services.is_valid_resource_schema'
    """
    service = session.query(models.Service).filter_by(type=service_type, resource_name=service_name).first()
    _ensure_sync_info_exists(service.resource_id, session)

    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service.resource_id, session)
    main_resource = session.query(models.RemoteResource).filter_by(
        resource_id=sync_info.remote_resource_id).first()
    tree = _get_resource_children(main_resource, session)

    remote_resources = _format_resource_tree(tree)
    return {service_name: {'children': remote_resources, 'resource_type': 'directory'}}


def get_last_sync(service_type, service_name, session):
    last_sync = None
    service = session.query(models.Service).filter_by(type=service_type, resource_name=service_name).first()
    _ensure_sync_info_exists(service.resource_id, session)
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service.resource_id, session)
    if sync_info:
        last_sync = sync_info.last_sync
    return last_sync


def fetch_all_services_by_type(service_type, session):
    """
    Get remote resources for all services of a certain type.
    :param service_type:
    :param session:
    """
    for service in session.query(models.Service).filter_by(type=service_type):
        # noinspection PyBroadException
        try:
            fetch_single_service(service, session)
        except:
            if CRON_SERVICE:
                LOGGER.exception("There was an error when fetching data from the url: %s" % service.url)
                pass
            else:
                raise


def fetch_single_service(service, session):
    """
    Get remote resources for a single service.
    :param service: (models.Service)
    :param session:
    """
    LOGGER.info("Requesting remote resources")
    remote_resources = _get_remote_resources(service)
    service_id = service.resource_id
    LOGGER.info("Deleting RemoteResource records for service: %s" % service.resource_name)
    _delete_records(service_id, session)
    _ensure_sync_info_exists(service.resource_id, session)
    LOGGER.info("Writing RemoteResource records to database")
    _update_db(remote_resources, service_id, session)


def fetch():
    """
    Main function to get all remote resources for each service and write to database.
    """
    LOGGER.info("Getting database url")
    url = db.get_db_url()

    LOGGER.debug("Database url: %s" % url)
    engine = create_engine(url)

    session = Session(bind=engine)

    for service_type in SYNC_SERVICES_TYPES:
        LOGGER.info("Fetching data for service type: %s" % service_type)
        fetch_all_services_by_type(service_type, session)

    session.commit()
    session.close()


def setup_cron_logger():
    log_path = constants.get_constant("MAGPIE_CRON_LOG")
    log_path = os.path.expandvars(log_path)
    log_path = os.path.expanduser(log_path)
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)8s %(message)s")
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)
    LOGGER.setLevel(logging.INFO)


def main():
    """
    Main entry point for cron service.
    """
    global CRON_SERVICE
    CRON_SERVICE = True

    setup_cron_logger()

    LOGGER.info("Magpie cron started.")

    try:
        db_ready = db.is_database_ready()
        if not db_ready:
            LOGGER.info("Database isn't ready")
            return
        LOGGER.info("Starting to fetch data for all service types")
        fetch()
    except Exception:
        LOGGER.exception("An error occured")
        raise

    LOGGER.info("Success, exiting.")


if __name__ == '__main__':
    fetch()
