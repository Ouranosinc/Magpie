from pyramid.httpexceptions import HTTPInternalServerError
from typing import TYPE_CHECKING
from ziggurat_foundations.models.services.resource import ResourceService

from magpie.api.exception import evaluate_call
from magpie.permissions import format_permissions
from magpie.services import SERVICE_TYPE_DICT

if TYPE_CHECKING:
    from sqlalchemy.orm.session import Session
    from typing import Iterable, Optional
    from magpie.models import Resource, Service
    from magpie.typedefs import AnyPermissionType, ChildrenResourceNodes, JSON, ServiceOrResourceType


def format_resource(resource, permissions=None, basic_info=False):
    # type: (Resource, Optional[Iterable[AnyPermissionType]], bool) -> JSON
    """
    Formats the :paramref:`resource` information into JSON.
    """
    def fmt_res(res, perms, info):
        result = {
            "resource_name": str(res.resource_name),
            "resource_display_name": str(res.resource_display_name or res.resource_name),
            "resource_type": str(res.resource_type),
            "resource_id": res.resource_id
        }
        if not info:
            result.update({
                "parent_id": res.parent_id,
                "root_service_id": res.root_service_id,
                "children": {},
                "permission_names": list() if perms is None else format_permissions(perms)
            })
        return result

    return evaluate_call(
        lambda: fmt_res(resource, permissions, basic_info),
        http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format resource.",
        content={"resource": repr(resource), "permissions": repr(permissions), "basic_info": str(basic_info)}
    )


def format_resource_tree(children, db_session, resources_perms_dict=None, *args):
    # type: (ChildrenResourceNodes, Session, Optional[ChildrenResourceNodes], Optional[ChildrenResourceNodes]) -> JSON
    """
    Generates the formatted resource tree under the provided children resources, with all of their children resources
    by calling :func:`format_resource` recursively.

    Filters resource permissions with ``resources_perms_dict`` if provided.

    :param children: service or resource for which to generate the formatted resource tree
    :param db_session: connection to db
    :param resources_perms_dict:
        Any pre-established :term:`Applied Permissions` to set to corresponding resources by ID.
        When provided, these will define the :term:`User`, :term:`Group` or both (i.e.: :term:`Inherited Permissions`)
        actual permissions, or even the :term:`Effective Permissions`, according to parent caller function's context.
        Otherwise (``None``), defaults to extracting :term:`Allowed Permissions`.
    :return: formatted resource tree
    """
    # optimization to avoid re-lookup of 'allowed permissions' when already fetched
    # unused when parsing 'applied permissions'
    __internal_svc_res_perm_dict = {} if not args else args[0]

    fmt_res_tree = {}
    for child_id, child_dict in children.items():
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

        fmt_res_tree[child_id] = format_resource(resource, perms)
        fmt_res_tree[child_id]["children"] = format_resource_tree(
            new_children,
            db_session,
            resources_perms_dict,
            __internal_svc_res_perm_dict
        )

    return fmt_res_tree


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
