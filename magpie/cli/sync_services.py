#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Sync registered services in Magpie with resources retrieved from actual service.

.. seealso::
    - :py:mod:`magpie.cli.sync_resources`
"""
import abc
from collections import OrderedDict, defaultdict
from typing import TYPE_CHECKING

import requests
import six
import threddsclient

from magpie.utils import CONTENT_TYPE_JSON

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Dict, Type

    from magpie.typedefs import AnyNestedChildrenTree, ServiceResourceTypeTree, Str


def is_valid_resource_schema(resources):
    # type: (AnyNestedChildrenTree) -> bool
    """
    Validates the resource structure.

    Expected dictionary is a tree of the following form:

    .. code-block:: json

        {
            "resource_name_1": {
                "children": {
                    "resource_name_3": {"children": {}},
                    "resource_name_4": {"children": {}}
                }
            }
            "resource_name_2": {"children": {}}
        }
    """
    for values in resources.values():
        if "children" not in values:
            return False
        if not isinstance(values["children"], (OrderedDict, dict)):
            return False
        return is_valid_resource_schema(values["children"])
    return True


@six.add_metaclass(abc.ABCMeta)
class SyncServiceInterface(object):
    sync_type = None    # type: Str

    def __init__(self, service_name, url):
        self.service_name = service_name
        self.url = url

    @property
    @abc.abstractmethod
    def max_depth(self):
        # type: () -> int
        """
        The max depth at which remote resources are fetched.
        """

    @abc.abstractmethod
    def get_resources(self):
        # type: () -> ServiceResourceTypeTree
        """
        This is the function actually fetching the data from the remote service. Implement this for every specific
        service.

        :return: The returned dictionary must be validated by 'is_valid_resource_schema'
        """


class SyncServiceGeoserver(SyncServiceInterface):
    sync_type = "geoserver-api"

    @property
    def max_depth(self):
        # type: () -> None
        return None

    def get_resources(self):
        # type: () -> ServiceResourceTypeTree

        # Only workspaces are fetched for now
        resource_type = "route"
        workspaces_url = "{}/{}".format(self.url, "workspaces")
        resp = requests.get(workspaces_url, headers={"Accept": CONTENT_TYPE_JSON})
        resp.raise_for_status()
        workspaces_list = resp.json().get("workspaces", {}).get("workspace", {})

        workspaces = {w["name"]: {"children": {}, "resource_type": resource_type} for w in workspaces_list}

        workspace_tree = {"workspaces": {"children": workspaces,
                                         "resource_type": resource_type}}

        resources = {"geoserver-api": {"children": workspace_tree,
                                       "resource_type": resource_type}}

        if not is_valid_resource_schema(resources):
            raise ValueError("Error in SyncServiceInterface implementation")
        return resources


class SyncServiceProjectAPI(SyncServiceInterface):
    sync_type = "project-api"

    @property
    def max_depth(self):
        # type: () -> None
        return None

    def get_resources(self):
        # type: () -> ServiceResourceTypeTree

        # Only workspaces are fetched for now
        resource_type = "route"
        projects_url = "/".join([self.url, "Projects"])
        resp = requests.get(projects_url)
        resp.raise_for_status()

        projects = {p["id"]: {"children": {},
                              "resource_type": resource_type,
                              "resource_display_name": p["name"]}
                    for p in resp.json()}

        resources = {self.service_name: {"children": projects, "resource_type": resource_type}}
        if not is_valid_resource_schema(resources):
            raise ValueError("Error in SyncServiceInterface implementation")
        return resources


class SyncServiceThredds(SyncServiceInterface):
    sync_type = "thredds"

    @property
    def max_depth(self):
        # type: () -> int
        return 3

    @staticmethod
    def _resource_id(resource):
        id_ = resource.name
        if len(resource.datasets) > 0:
            id_ = resource.datasets[0].ID.split("/")[-1]
        return id_

    def get_resources(self):
        # type: () -> ServiceResourceTypeTree
        def thredds_get_resources(url, depth):
            cat = threddsclient.read_url(url, timeout=5)
            name = self._resource_id(cat)
            if depth == self.max_depth:
                name = self.service_name
            resource_type = "directory"
            if cat.datasets and cat.datasets[0].content_type != "application/directory":
                resource_type = "file"

            tree_item = {name: {"children": {}, "resource_type": resource_type}}

            if depth > 0:
                for reference in cat.flat_references():
                    tree_item[name]["children"].update(thredds_get_resources(reference.url, depth - 1))

            return tree_item

        resources = thredds_get_resources(self.url, self.max_depth)
        if not is_valid_resource_schema(resources):
            raise ValueError("Error in SyncServiceInterface implementation")
        return resources


class SyncServiceDefault(SyncServiceInterface):
    @property
    def max_depth(self):
        # type: () -> None
        return None

    def get_resources(self):
        # type: () -> ServiceResourceTypeTree
        return {}


SYNC_SERVICES_TYPES = defaultdict(lambda: SyncServiceDefault)   # type: Dict[Str, Type[SyncServiceInterface]]
for sync_svc in [SyncServiceThredds, SyncServiceGeoserver, SyncServiceProjectAPI]:
    if sync_svc.sync_type in SYNC_SERVICES_TYPES:
        raise KeyError("Duplicate sync service type identifiers not allowed")
    SYNC_SERVICES_TYPES[sync_svc.sync_type] = sync_svc
