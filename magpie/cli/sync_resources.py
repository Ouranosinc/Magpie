#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Synchronize local and remote resources.

To implement a new service, see :class:`magpie.cli.sync_services.SyncServiceInterface`.

.. seealso::
    - :py:mod:`magpie.cli.sync_services`
"""
import argparse
import copy
import datetime
import logging
import os
import sys
from collections import OrderedDict
from typing import TYPE_CHECKING

import transaction

from magpie import constants, db, models
from magpie.api.management.resource.resource_utils import get_resource_children
from magpie.cli.sync_services import SYNC_SERVICES_TYPES, SyncServiceDefault, is_valid_resource_schema
from magpie.cli.utils import make_logging_options, setup_logger_from_options
from magpie.utils import get_logger

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Optional, Sequence, Union

    from sqlalchemy.orm.session import Session

    from magpie.models import Service
    from magpie.typedefs import JSON, RemoteResourceTree, ServiceResourceNodeTree, SettingsType, Str

LOGGER = get_logger(__name__)

CRON_SERVICE = False

OUT_OF_SYNC = datetime.timedelta(hours=3)

# try to instantiate classes right away
for sync_service_class in SYNC_SERVICES_TYPES.values():
    name, url = "", ""
    sync_service_class(name, url)


def merge_local_and_remote_resources(resources_local, service_sync_type, service_id, session):
    # type: (RemoteResourceTree, Str, int, Session) -> RemoteResourceTree
    """
    Main function to sync resources with remote server.
    """
    if not get_last_sync(service_id, session):
        return resources_local
    remote_resources = _query_remote_resources_in_database(service_id, session=session)
    max_depth = SYNC_SERVICES_TYPES[service_sync_type]("", "").max_depth
    merged_resources = _merge_resources(resources_local, remote_resources, max_depth)
    _sort_resources(merged_resources)
    return merged_resources


def _merge_resources(resources_local, resources_remote, max_depth=None):
    # type: (RemoteResourceTree, RemoteResourceTree, Optional[int]) -> RemoteResourceTree
    """
    Merge resources_local and resources_remote, adding the following keys to the output:

        - remote_id: id of the RemoteResource
        - matches_remote: True or False depending if the resource is present on the remote server

    :returns: Dictionary tree of the merged resources.
    """
    if not resources_remote:
        return resources_local

    if not is_valid_resource_schema(resources_local):
        raise ValueError("Invalid 'local' resource schema.")
    if not is_valid_resource_schema(resources_remote):
        raise ValueError("Invalid 'remote' resource schema.")
    if not resources_local:
        raise ValueError("The resources must contain at least the service name.")

    # don't overwrite the input arguments
    merged_resources = copy.deepcopy(resources_local)

    def recurse(_resources_local, _resources_remote, depth=0):
        # loop local resources, looking for matches in remote resources
        for resource_name_local, values in _resources_local.items():
            matches_remote = resource_name_local in _resources_remote
            remote_id = _resources_remote.get(resource_name_local, {}).get("remote_id", "")
            deeper_than_fetched = depth >= max_depth if max_depth is not None else False

            values["remote_id"] = remote_id
            values["matches_remote"] = matches_remote or deeper_than_fetched

            resource_remote_children = _resources_remote[resource_name_local]["children"] if matches_remote else {}
            recurse(values["children"], resource_remote_children, depth + 1)

        # loop remote resources, looking for matches in local resources
        for resource_name_remote, values in _resources_remote.items():
            if resource_name_remote not in _resources_local:
                new_resource = {
                    "permission_names": [],
                    "permissions": [],
                    "children": {},
                    "id": None,
                    "remote_id": values["remote_id"],
                    "resource_type": values["resource_type"],
                    "resource_display_name": values.get("resource_display_name", resource_name_remote),
                    "matches_remote": True,
                }
                _resources_local[resource_name_remote] = new_resource
                recurse(new_resource["children"], values["children"], depth + 1)

    recurse(merged_resources, resources_remote)

    if not is_valid_resource_schema(merged_resources):
        raise ValueError("Invalid resulting 'merged' resource schema from 'local' and 'remote' resources syncing.")

    return merged_resources


def _sort_resources(resources):
    # type: (RemoteResourceTree) -> None
    """
    Sorts a nested resource dictionary.

    The dictionary is expected to be valid as per :func:`sync_services.is_valid_resource_schema`.

    :return: None. Inplace modification.
    """
    for values in resources.values():
        values["children"] = OrderedDict(sorted(values["children"].items()))
        return _sort_resources(values["children"])


def _ensure_sync_info_exists(service_resource_id, session):
    # type: (int, Session) -> None
    """
    Make sure the RemoteResourcesSyncInfo entry exists in the database.
    """
    service_sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_resource_id, session)
    if not service_sync_info:
        sync_info = models.RemoteResourcesSyncInfo(service_id=service_resource_id)  # noqa
        session.add(sync_info)
        session.flush()
        _create_main_resource(service_resource_id, session)


def _get_remote_resources(service):
    # type: (models.Service) -> JSON
    """
    Request remote resources, depending on service type.

    :param service: service for which to fetch remove children resources
    :return: nested content as ``{"node_name": {"children": JSON, "resource_type": "resource_type"}}``
    """
    service_url = service.url
    if service_url.endswith("/"):  # remove trailing slash
        service_url = service_url[:-1]

    sync_svc_cls = SYNC_SERVICES_TYPES.get(service.sync_type.lower(), SyncServiceDefault)  # noqa: W0212
    sync_service = sync_svc_cls(service.resource_name, service_url)
    return sync_service.get_resources()


def _delete_records(service_id, session):
    """
    Delete all RemoteResource based on a Service.resource_id.
    """
    session.query(models.RemoteResource).filter_by(service_id=service_id).delete()
    session.flush()


def _create_main_resource(service_id, session):
    # type: (int, Session) -> None
    """
    Creates a main resource for a service, whether one currently exists or not.

    Each RemoteResourcesSyncInfo has a main RemoteResource of the same name as the service.
    This is similar to the Service and Resource relationship.
    """
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_id, session)
    main_resource = models.RemoteResource(service_id=service_id,
                                          resource_name=str(sync_info.service.resource_name),
                                          resource_type="directory")  # noqa
    session.add(main_resource)
    session.flush()
    sync_info.remote_resource_id = main_resource.resource_id
    session.flush()


def _update_db(remote_resources, service_id, session):
    # type: (RemoteResourceTree, int, Session) -> None
    """
    Writes remote resources to database.
    """
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_id, session)

    def add_children(resources, parent_id, position=0):
        for resource_name, values in resources.items():
            resource_display_name = str(values.get("resource_display_name", resource_name))
            new_resource = models.RemoteResource(service_id=sync_info.service_id,
                                                 resource_name=str(resource_name),
                                                 resource_display_name=resource_display_name,
                                                 resource_type=values["resource_type"],
                                                 parent_id=parent_id,
                                                 ordering=position)  # noqa
            session.add(new_resource)
            session.flush()
            position += 1
            add_children(values["children"], new_resource.resource_id)

    first_item = list(remote_resources)[0]
    add_children(remote_resources[first_item]["children"], sync_info.remote_resource_id)

    sync_info.last_sync = datetime.datetime.now()

    session.flush()


def _format_resource_tree(children):
    # type: (ServiceResourceNodeTree) -> RemoteResourceTree
    fmt_res_tree = {}
    for child_dict in children.values():
        resource = child_dict["node"]
        new_children = child_dict["children"]
        resource_display_name = resource.resource_display_name or resource.resource_name
        resource_dict = {
            "children": _format_resource_tree(new_children),
            "remote_id": resource.resource_id,
            "resource_type": resource.resource_type,
            "resource_display_name": resource_display_name,
        }
        fmt_res_tree[resource.resource_name] = resource_dict
    return fmt_res_tree


def _query_remote_resources_in_database(service_id, session):
    # type: (int, Session) -> RemoteResourceTree
    """
    Reads remote resources from the RemoteResources table. No external request is made.

    :return: Dictionary of the form defined in :func:`sync_services.is_valid_resource_schema`.
    """
    service = session.query(models.Service).filter_by(resource_id=service_id).first()
    _ensure_sync_info_exists(service_id, session)

    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_id, session)
    main_resource = session.query(models.RemoteResource).filter_by(
        resource_id=sync_info.remote_resource_id).first()
    tree = get_resource_children(main_resource, session, models.REMOTE_RESOURCE_TREE_SERVICE)

    remote_resources = _format_resource_tree(tree)
    remote_service = {
        service.resource_name: {
            "children": remote_resources,
            "resource_type": "service",
            "remote_id": main_resource.resource_id,
        }
    }
    return remote_service


def get_last_sync(service_id, session):
    # type: (int, Session) -> Optional[datetime.datetime]
    """
    Obtain the date-time of the last known sync event for a service.
    """
    last_sync = None
    _ensure_sync_info_exists(service_id, session)
    sync_info = models.RemoteResourcesSyncInfo.by_service_id(service_id, session)
    if sync_info:
        last_sync = sync_info.last_sync
    return last_sync


def fetch_all_services_by_type(service_type, session):
    # type: (Str, Session) -> None
    """
    Get remote resources for all services of a certain type.

    :param service_type: Service type for which all corresponding services will be synchronized.
    :param session: Database connexion to apply synchronization changes.
    """
    for service in session.query(models.Service).filter_by(type=service_type):
        try:
            fetch_single_service(service, session)
        except Exception:  # noqa # nosec: B110
            LOGGER.exception("There was an error when fetching data from the URL: [%s]", service.url)
            if CRON_SERVICE:
                pass
            raise


def fetch_single_service(service, session):
    # type: (Union[Service, int], Session) -> None
    """
    Get remote resources for a single service.

    :param service: Specific service for which to synchronize remote resources.
    :param session: Database connexion to apply synchronization changes.
    """
    if isinstance(service, int):
        service = session.query(models.Service).filter_by(resource_id=service).first()
    if not service.sync_type:
        LOGGER.info("Skipping service [%s] with no sync type defined.", service.resource_name)
        return
    LOGGER.info("Requesting remote resources")
    remote_resources = _get_remote_resources(service)
    service_id = service.resource_id
    LOGGER.info("Deleting RemoteResource records for service: %s", service.resource_name)
    _delete_records(service_id, session)
    _ensure_sync_info_exists(service.resource_id, session)
    LOGGER.info("Writing RemoteResource records to database")
    _update_db(remote_resources, service_id, session)


def fetch(settings=None):
    # type: (Optional[SettingsType]) -> None
    """
    Main function to get all remote resources for each service and write to database.
    """
    with transaction.manager:
        LOGGER.info("Getting database session")
        session = db.get_db_session_from_settings(settings=settings, echo=False)

        for service_type in SYNC_SERVICES_TYPES:
            LOGGER.info("Fetching data for service type: %s", service_type)
            fetch_all_services_by_type(service_type, session)

        transaction.commit()


def setup_cron_logger(log_level=logging.INFO):
    # type: (Union[Str, int]) -> None

    if not isinstance(log_level, int):
        log_level = logging.getLevelName(log_level)

    log_path = constants.get_constant("MAGPIE_CRON_LOG")
    log_path = os.path.expandvars(log_path)
    log_path = os.path.expanduser(log_path)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(log_level)
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(log_level)

    formatter = logging.Formatter("%(asctime)s %(levelname)8s %(message)s")
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(stream_handler)

    LOGGER.setLevel(log_level)


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Synchronize local and remote resources based on "
                                                 "Magpie Service sync-type.")
    make_logging_options(parser)
    parser.add_argument("--db", metavar="CONNECTION_URL", dest="db",
                        help="Magpie database URL to connect to. Otherwise, employ typical environment variables.")
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    """
    Main entry point for cron service.
    """
    global CRON_SERVICE  # pylint: disable=W0603,global-statement
    CRON_SERVICE = True

    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, args)
    settings = {"magpie.db_url": args.db} if args.db else None

    setup_cron_logger(args.log_level)
    LOGGER.info("Magpie cron started.")

    try:
        db_ready = db.is_database_ready(container=settings)
        if not db_ready:
            LOGGER.info("Database isn't ready")
            return
        LOGGER.info("Starting to fetch data for all service types")
        fetch(settings=settings)
    except Exception:
        LOGGER.exception("An error occurred")
        raise

    LOGGER.info("Success, exiting.")


if __name__ == "__main__":
    main()
