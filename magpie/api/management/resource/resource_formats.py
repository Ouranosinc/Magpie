from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPInternalServerError
from ziggurat_foundations.models.services.resource import ResourceService

from magpie.api.exception import evaluate_call
from magpie.permissions import PermissionType, format_permissions
from magpie.services import SERVICE_TYPE_DICT

if TYPE_CHECKING:
    from typing import Collection, List, Optional

    from sqlalchemy.orm.session import Session

    from magpie.models import Resource, Service
    from magpie.typedefs import (
        JSON,
        AnyPermissionType,
        NestedResourceNodes,
        NestingKeyType,
        ResourcePermissionMap,
        ServiceOrResourceType,
        Str
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
    def fmt_res():  # type: () -> JSON
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
            })
            result.update(format_permissions(permissions, permission_type))
        return result

    return evaluate_call(
        lambda: fmt_res(),
        http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format resource.",
        content={"resource": repr(resource), "permissions": repr(permissions), "basic_info": basic_info}
    )


def format_resource_tree(
    nested_resources,           # type: NestedResourceNodes
    db_session,                 # type: Session
    resources_perms_dict=None,  # type: Optional[ResourcePermissionMap]
    permission_type=None,       # type: Optional[PermissionType]
    nesting_key="children",     # type: NestingKeyType
):                              # type: (...) -> JSON
    """
    Generates the formatted resource tree under the provided nested resources.

    For all of the nested resources, formatting is applied by calling :func:`format_resource` recursively on them.
    Apply specific resource permissions as defined by :paramref:`resources_perms_dict` if provided.

    :param nested_resources: Service or resource for which to generate the formatted resource tree.
    :param db_session: Connection to database.
    :param resources_perms_dict:
        Any pre-established :term:`Applied Permission` to set to corresponding resources by ID.
        When provided, these will define the :term:`User`, :term:`Group` or both
        (i.e.: :term:`Inherited Permissions <Inherited Permission>`)
        actual permissions, or even the :term:`Effective Permissions <Effective Permission>`, according to parent
        caller function's context.
        Otherwise (``None``), defaults to extracting :term:`Allowed Permissions <Allowed Permission>` for the given
        :term:`Resource` scoped under the corresponding root :term:`Service`.
    :param permission_type:
        Override :term:`Permission` type to indicate its provenance.
        Type is applied recursively for all resources in the generated nested resource tree.
    :param nesting_key:
        Key to employ for nesting the formatted sub-tree resources according to the provided nested resources.
    :return: Formatted nested resource tree with their details and permissions.
    """
    # optimization to avoid re-lookup of 'allowed permissions' when already fetched
    # unused when parsing 'applied permissions'
    __internal_svc_res_perm_dict = {}

    def recursive_fmt_res_tree(nested_dict):  # type: (NestedResourceNodes) -> JSON
        fmt_res_tree = {}
        for child_id, child_dict in nested_dict.items():
            resource = child_dict["node"]
            # nested nodes always use 'children' regardless of nested-key
            # nested-key employed in the generated format will indicate the real resource parents/children relationship
            new_nested = child_dict["children"]
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
                # in case of inverse nesting, service could be at "bottom"
                # retrieve its permissions directly since its type is never expected nested under itself
                res_type_name = resource.resource_type  # type: Str
                if res_type_name == "service":
                    perms = SERVICE_TYPE_DICT[service.type].permissions
                else:
                    perms = __internal_svc_res_perm_dict[service_id][resource.resource_type]

            fmt_res_tree[child_id] = format_resource(resource, perms, permission_type)
            fmt_res_tree[child_id][nesting_key] = recursive_fmt_res_tree(new_nested)
        return fmt_res_tree

    return recursive_fmt_res_tree(nested_resources)


def format_resources_listed(resources, db_session):
    # type: (List[ServiceOrResourceType], Session) -> List[JSON]
    """
    Obtains the formatted :term:`Resource` list with their applicable permissions.
    """
    from magpie.api.management.resource import resource_utils as ru

    res_list = []
    for res in resources:
        res_perms = ru.get_resource_permissions(res, db_session=db_session)
        res_json = format_resource(res, permissions=res_perms)
        res_list.append(res_json)
    return res_list


def format_resources_nested(resource, nested_resources, nesting_key, db_session):
    # type: (ServiceOrResourceType, NestedResourceNodes, NestingKeyType, Session) -> JSON
    """
    Obtains the formatted :term:`Resource` tree with all its formatted children hierarchy.
    """
    from magpie.api.management.resource import resource_utils as ru

    resource_permissions = ru.get_resource_permissions(resource, db_session=db_session)
    resource_formatted = format_resource(resource, permissions=resource_permissions)
    resource_formatted[nesting_key] = format_resource_tree(
        nested_resources, nesting_key=nesting_key, db_session=db_session
    )
    return resource_formatted
