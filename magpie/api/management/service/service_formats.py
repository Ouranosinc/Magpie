from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPInternalServerError

from magpie.api.exception import evaluate_call
from magpie.api.management.resource.resource_formats import format_resource_tree
from magpie.api.management.resource.resource_utils import crop_tree_with_permission, get_resource_children
from magpie.permissions import PermissionType, format_permissions
from magpie.services import SERVICE_TYPE_DICT
from magpie.utils import get_twitcher_protected_service_url

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import List, Optional, Type

    from sqlalchemy.orm.session import Session

    from magpie.models import Resource, Service
    from magpie.permissions import PermissionSet
    from magpie.services import ServiceInterface
    from magpie.typedefs import JSON, ResourcePermissionMap


def format_service(service,                         # type: Service
                   permissions=None,                # type: Optional[List[PermissionSet]]
                   permission_type=None,            # type: Optional[PermissionType]
                   show_private_url=False,          # type: bool
                   show_public_url=True,            # type: bool
                   show_resources_allowed=False,    # type: bool
                   show_configuration=False,        # type: bool
                   basic_info=False,                # type: bool
                   dotted=False,                    # type: bool
                   ):                               # type: (...) -> JSON
    """
    Formats a :term:`Service` information into JSON.

    .. note::
        Automatically finds :paramref:`permissions` of the :paramref:`service` if not specified.
        To preserve `empty` permissions such as during listing of `user`/`group` resource permissions,
        an empty ``list`` should be specified.

    :param service: :term:`Service` to be formatted.
    :param permissions:
        Permissions to list along with the :paramref:`resource`.
        By default, these are the applicable permissions for that corresponding resource type.
    :param permission_type:
        Override indication of provenance to apply to :paramref:`permissions`. Only applicable when they are provided.
    :param show_private_url: Display the protected and private URL employed at service registration.
    :param show_public_url: Display the generated public URL from configured :ref:`config_twitcher`.
    :param show_resources_allowed: Display children resource details.
    :param show_configuration: Display the applicable configuration of the :term:`Service` if it supports it.
    :param basic_info:
        If ``True``, return only sufficient details to identify the service, without any additional details about
        :paramref:`permissions`, children resources or configuration information is returned.
    :param dotted:
        Employ a dot (``.``) instead of underscore (``_``) to separate :term:`Service` from its basic information.

    .. seealso::
        :func:`magpie.api.management.resource.resource_formats.format_resource`
    """
    def fmt_svc():
        sep = "." if dotted else "_"
        svc_sync_type = str(service.sync_type) if service.sync_type is not None else service.sync_type
        svc_info = {
            "service{}name".format(sep): str(service.resource_name),
            "service{}type".format(sep): str(service.type),
            "service{}sync_type".format(sep): svc_sync_type,
            "resource{}id".format(sep): service.resource_id,
        }
        if show_public_url:
            svc_public_url = "service.public_url" if dotted else "public_url"  # backward compat
            svc_info[svc_public_url] = str(get_twitcher_protected_service_url(service.resource_name))
        if show_private_url:
            svc_info["service{}url".format(sep)] = str(service.url)
        if basic_info:
            return svc_info
        if show_configuration:
            svc_info["configuration"] = service.configuration
        svc_type = SERVICE_TYPE_DICT[service.type]
        perms = svc_type.permissions if permissions is None else permissions
        svc_info.update(format_permissions(perms, permission_type))
        if show_resources_allowed:
            svc_info["resource_child_allowed"] = svc_type.child_resource_allowed
            svc_info["resource_types_allowed"] = sorted(svc_type.resource_type_names)
            svc_info["resource_structure_allowed"] = sorted(svc_type.child_structure_allowed)
        return svc_info

    return evaluate_call(
        lambda: fmt_svc(),
        http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format service.",
        content={"service": repr(service), "permissions": repr(permissions)}
    )


def format_service_resources(service,                       # type: Service
                             db_session,                    # type: Session
                             service_perms=None,            # type: Optional[List[PermissionSet]]
                             resources_perms_dict=None,     # type: Optional[ResourcePermissionMap]
                             permission_type=None,          # type: Optional[PermissionType]
                             show_all_children=False,       # type: bool
                             show_private_url=True,         # type: bool
                             ):                             # type: (...) -> JSON
    """
    Formats the service and its children resource tree as a JSON body.

    :param service: service for which to display details with sub-resources
    :param db_session: database session
    :param service_perms:
        If provided, sets :term:`Applied Permissions` to display on the formatted :paramref:`service`.
        Otherwise, sets the :term:`Allowed Permissions` specific to the :paramref:`service`'s type.
    :param resources_perms_dict:
        If provided (not ``None``), set the :term:`Applied Permissions` on each specified resource matched by ID.
        If ``None``, retrieve and set :term:`Allowed Permissions` for the corresponding resources under the service.
        To set empty :term:`Applied Permissions` (e.g.: :term:`User` doesn't have permissions on that resource), provide
        an explicit empty dictionary instead.
    :param permission_type: Provide permission type being rendered.
    :param show_all_children:
        Display all children resources recursively, or only ones specified by ID with :paramref:`resources_perms_dict`.
    :param show_private_url: displays the
    :return: JSON body representation of the service resource tree
    """
    def fmt_svc_res(svc, db, svc_perms, res_perms, show_all):
        tree = get_resource_children(svc, db)
        if not show_all:
            filter_res_ids = list(res_perms) if res_perms else []
            tree, _ = crop_tree_with_permission(tree, filter_res_ids)

        svc_perms = SERVICE_TYPE_DICT[svc.type].permissions if svc_perms is None else svc_perms
        svc_res = format_service(svc, svc_perms, permission_type, show_private_url=show_private_url)
        svc_res["resources"] = format_resource_tree(tree, resources_perms_dict=res_perms,
                                                    permission_type=permission_type, db_session=db)
        return svc_res

    return evaluate_call(
        lambda: fmt_svc_res(service, db_session, service_perms, resources_perms_dict, show_all_children),
        fallback=lambda: db_session.rollback(), http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format service resources tree",
        content=format_service(service, service_perms, permission_type, show_private_url=show_private_url)
    )


def format_service_resource_type(resource_class, service_class):
    # type: (Type[Resource], Type[ServiceInterface]) -> JSON
    svc_res_info = {
        "resource_type": resource_class.resource_type_name,
        "resource_child_allowed": resource_class.child_resource_allowed,
    }
    svc_res_perm = service_class.get_resource_permissions(resource_class.resource_type_name)
    svc_res_info.update(format_permissions(svc_res_perm, PermissionType.ALLOWED))
    return svc_res_info
