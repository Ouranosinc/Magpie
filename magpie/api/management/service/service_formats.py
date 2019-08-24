from magpie.api.exception import evaluate_call
from magpie.api.management.resource.resource_utils import crop_tree_with_permission
from magpie.api.management.resource.resource_formats import get_resource_children, format_resource_tree
from magpie.definitions.pyramid_definitions import HTTPInternalServerError
from magpie.permissions import format_permissions
from magpie.utils import get_twitcher_protected_service_url
from magpie.services import SERVICE_TYPE_DICT
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Optional, JSON, Str, Dict, List, Type  # noqa: F401
    from magpie.definitions.sqlalchemy_definitions import Session  # noqa: F401
    from magpie.models import Resource, Service  # noqa: F401
    from magpie.permissions import Permission  # noqa: F401
    from magpie.services import ServiceInterface  # noqa: F401


def format_service(service, permissions=None, show_private_url=False, show_resources_allowed=False):
    # type: (Service, Optional[List[Permission]], bool, bool) -> JSON
    """
    Formats the ``service`` information into JSON.

    Note:
        Automatically finds ``permissions`` of the service if not specified.
        To preserve `empty` permissions such as during listing of `user`/`group` resource permissions,
        an empty ``list`` should be specified.
    """
    def fmt_svc(svc, perms):

        svc_info = {
            u"public_url": str(get_twitcher_protected_service_url(svc.resource_name)),
            u"service_name": str(svc.resource_name),
            u"service_type": str(svc.type),
            u"service_sync_type": str(svc.sync_type) if svc.sync_type is not None else svc.sync_type,
            u"resource_id": svc.resource_id,
        }
        if perms is None:  # user/group permission specify empty list
            perms = SERVICE_TYPE_DICT[svc.type].permissions
        svc_info[u"permission_names"] = format_permissions(perms)
        if show_private_url:
            svc_info[u"service_url"] = str(svc.url)
        if show_resources_allowed:
            svc_info[u"resource_types_allowed"] = sorted(SERVICE_TYPE_DICT[svc.type].resource_type_names)
            svc_info[u"resource_child_allowed"] = SERVICE_TYPE_DICT[svc.type].child_resource_allowed
        return svc_info

    return evaluate_call(
        lambda: fmt_svc(service, permissions),
        httpError=HTTPInternalServerError,
        msgOnFail="Failed to format service.",
        content={u"service": repr(service), u"permissions": repr(permissions)}
    )


def format_service_resources(service,                       # type: Service
                             db_session,                    # type: Session
                             service_perms=None,            # type: Optional[List[Permission]]
                             resources_perms_dict=None,     # type: Optional[Dict[Str, List[Str]]]
                             show_all_children=False,       # type: bool
                             show_private_url=True,         # type: bool
                             ):                             # type: (...) -> JSON
    """
    Formats the service and its resource tree as a JSON body.

    :param service: service for which to display details with sub-resources
    :param db_session: database session
    :param service_perms: permissions to display instead of specific ``service``-type ones
    :param resources_perms_dict: permission(s) of resource(s) id(s) to *preserve* if ``resources_perms_dict = False``
    :param show_all_children: display all children resources recursively, or only ones matching ``resources_perms_dict``
    :param show_private_url: displays the
    :return: JSON body representation of the service resource tree
    """
    def fmt_svc_res(svc, db, svc_perms, res_perms, show_all):
        tree = get_resource_children(svc, db)
        if not show_all:
            tree, resource_id_list_remain = crop_tree_with_permission(tree, list(res_perms.keys()))

        svc_perms = SERVICE_TYPE_DICT[svc.type].permissions if svc_perms is None else svc_perms
        svc_res = format_service(svc, svc_perms, show_private_url=show_private_url)
        svc_res[u"resources"] = format_resource_tree(tree, resources_perms_dict=res_perms, db_session=db)
        return svc_res

    return evaluate_call(
        lambda: fmt_svc_res(service, db_session, service_perms, resources_perms_dict or {}, show_all_children),
        fallback=lambda: db_session.rollback(), httpError=HTTPInternalServerError,
        msgOnFail="Failed to format service resources tree",
        content=format_service(service, service_perms, show_private_url=show_private_url)
    )


def format_service_resource_type(resource_class, service_class):
    # type: (Type[Resource], Type[ServiceInterface]) -> JSON
    return {
        u"resource_type": resource_class.resource_type_name,
        u"resource_child_allowed": resource_class.child_resource_allowed,
        u"permission_names": format_permissions(
            service_class.get_resource_permissions(resource_class.resource_type_name)
        ),
    }
