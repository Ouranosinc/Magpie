from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPInternalServerError
from ziggurat_foundations.models.services.resource import ResourceService

from magpie.api.exception import evaluate_call
from magpie.permissions import PermissionType, format_permissions
from magpie.services import SERVICE_TYPE_DICT

if TYPE_CHECKING:
    from typing import Collection, Optional

    from sqlalchemy.orm.session import Session

    from magpie.models import Resource, Service
    from magpie.typedefs import (
        JSON,
        AnyPermissionType,
        ChildrenResourceNodes,
        ResourcePermissionMap,
        ServiceOrResourceType
    )


def format_resource(resource, permissions=None, permission_type=None, basic_info=False, dotted=False):
    # type: (Resource, Optional[Collection[AnyPermissionType]], Optional[PermissionType], bool, bool) -> JSON
    """
    Formats a :term:`Resource` information into JSON.

    :param resource: :term:`Resource` to be formatted.
    :param permissions:
        Permissions to list along with the :paramref:`resource`.
        By default, these are the applicable permissions for that corresponding resource type.
    :param permission_type:
        Override indication of provenance to apply to :paramref:`permissions`. Only applicable when they are provided.
    :param basic_info:
        If ``True``, return only sufficient details to identify the resource, without any additional
        :paramref:`permissions` detail, nor hierarchical :paramref:`resource` information is returned.
    :param dotted:
        Employ a dot (``.``) instead of underscore (``_``) to separate :term:`Resource` from its basic information.

    .. seealso::
        :func:`magpie.api.management.service.service_formats.format_service`
    """
    def fmt_res():
        sep = "." if dotted else "_"
        result = {
            "resource{}name".format(sep): str(resource.resource_name),
            "resource{}display_name".format(sep): str(resource.resource_display_name or resource.resource_name),
            "resource{}type".format(sep): str(resource.resource_type),
            "resource{}id".format(sep): resource.resource_id
        }
        if not basic_info:
            result.update({
                "parent_id": resource.parent_id,
                "root_service_id": resource.root_service_id,
                "children": {},
            })
            result.update(format_permissions(permissions, permission_type))
        return result

    return evaluate_call(
        lambda: fmt_res(),
        http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format resource.",
        content={"resource": repr(resource), "permissions": repr(permissions), "basic_info": basic_info}
    )


def format_resource_tree(children, db_session, resources_perms_dict=None, permission_type=None):
    # type: (ChildrenResourceNodes, Session, Optional[ResourcePermissionMap], Optional[PermissionType]) -> JSON
    """
    Generates the formatted resource tree under the provided children resources, with all of their children resources by
    calling :func:`format_resource` recursively on them.

    Apply specific resource permissions as defined by :paramref:`resources_perms_dict` if provided.

    :param children: service or resource for which to generate the formatted resource tree
    :param db_session: connection to db
    :param resources_perms_dict:
        Any pre-established :term:`Applied Permission` to set to corresponding resources by ID.
        When provided, these will define the :term:`User`, :term:`Group` or both
        (i.e.: :term:`Inherited Permissions <Inherited Permission>`)
        actual permissions, or even the :term:`Effective Permissions <Effective Permission>`, according to parent
        caller function's context.
        Otherwise (``None``), defaults to extracting :term:`Allowed Permissions <Allowed Permission>` for the given
        :term:`Resource` scoped under the corresponding root :term:`Service`.
    :return: formatted resource tree
    """
    # optimization to avoid re-lookup of 'allowed permissions' when already fetched
    # unused when parsing 'applied permissions'
    __internal_svc_res_perm_dict = {}

    def recursive_fmt_res_tree(children_dict):
        fmt_res_tree = {}
        for child_id, child_dict in children_dict.items():
            resource = child_dict["node"]
            new_children = child_dict["children"]
            perms = []

            # case of pre-specified user/group-specific permissions
            if resources_perms_dict is not None:
                if resource.resource_id in resources_perms_dict.keys():
                    perms = resources_perms_dict[resource.resource_id]

            # case of full fetch (allowed resource permissions)
            else:
                # directly access the resource if it is a service
                service = None  # type: Optional[Service]
                if resource.root_service_id is None:
                    service = resource
                    service_id = resource.resource_id
                # obtain corresponding top-level service resource if not already available,
                # get resource permissions allowed under the top service's scope
                else:
                    service_id = resource.root_service_id
                    if service_id not in __internal_svc_res_perm_dict:
                        service = ResourceService.by_resource_id(service_id, db_session=db_session)
                # add to dict only if not already added
                if service is not None and service_id not in __internal_svc_res_perm_dict:
                    __internal_svc_res_perm_dict[service_id] = {
                        res_type.resource_type_name: res_perms  # use str key to match below 'resource_type' field
                        for res_type, res_perms in SERVICE_TYPE_DICT[service.type].resource_types_permissions.items()
                    }
                perms = __internal_svc_res_perm_dict[service_id][resource.resource_type]  # 'resource_type' is str here

            fmt_res_tree[child_id] = format_resource(resource, perms, permission_type)
            fmt_res_tree[child_id]["children"] = recursive_fmt_res_tree(new_children)
        return fmt_res_tree

    return recursive_fmt_res_tree(children)


def format_resource_with_children(resource, db_session):
    # type: (ServiceOrResourceType, Session) -> JSON
    """
    Obtains the formatted :term:`Resource` tree with all its formatted children hierarchy.
    """
    from magpie.api.management.resource import resource_utils as ru

    resource_permissions = ru.get_resource_permissions(resource, db_session=db_session)
    resource_formatted = format_resource(resource, permissions=resource_permissions)

    resource_formatted["children"] = format_resource_tree(
        ru.get_resource_children(resource, db_session),
        db_session=db_session
    )
    return resource_formatted
