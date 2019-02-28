from magpie.api.api_except import evaluate_call
from magpie.api.management.resource.resource_utils import crop_tree_with_permission
from magpie.api.management.resource.resource_formats import get_resource_children, format_resource_tree
from magpie.definitions.pyramid_definitions import *
from magpie.definitions.sqlalchemy_definitions import Session
from magpie.utils import get_twitcher_protected_service_url
from magpie.models import Resource, Service
from magpie.services import service_type_dict, ServiceI
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Optional, JsonBody, AnyStr, Dict, List


def format_service(service, permissions=None, show_private_url=False, show_resources_allowed=False):
    # type: (Service, Optional[bool], Optional[bool], Optional[bool]) -> JsonBody
    def fmt_svc(svc, perms):
        svc_info = {
            u'public_url': str(get_twitcher_protected_service_url(svc.resource_name)),
            u'service_name': str(svc.resource_name),
            u'service_type': str(svc.type),
            u'service_sync_type': str(svc.sync_type) if svc.sync_type is not None else svc.sync_type,
            u'resource_id': svc.resource_id,
            u'permission_names': sorted(service_type_dict[svc.type].permission_names if perms is None else perms)
        }
        if show_private_url:
            svc_info[u'service_url'] = str(svc.url)
        if show_resources_allowed:
            svc_info[u'resource_types_allowed'] = sorted(service_type_dict[svc.type].resource_types)
            svc_info[u'resource_child_allowed'] = service_type_dict[svc.type].child_resource_allowed
        return svc_info

    return evaluate_call(
        lambda: fmt_svc(service, permissions),
        httpError=HTTPInternalServerError,
        msgOnFail="Failed to format service.",
        content={u'service': repr(service), u'permissions': repr(permissions)}
    )


def format_service_resources(service,                       # type: Service
                             db_session,                    # type: Session
                             service_perms=None,            # type: Optional[List[AnyStr]]
                             resources_perms_dict=None,     # type: Optional[Dict[AnyStr, List[AnyStr]]]
                             show_all_children=False,       # type: Optional[bool]
                             show_private_url=True,         # type: Optional[bool]
                             ):                             # type: (...) -> JsonBody
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

        svc_perms = service_type_dict[svc.type].permission_names if svc_perms is None else svc_perms
        svc_res = format_service(svc, svc_perms, show_private_url=show_private_url)
        svc_res[u'resources'] = format_resource_tree(tree, resources_perms_dict=res_perms, db_session=db)
        return svc_res

    return evaluate_call(
        lambda: fmt_svc_res(service, db_session, service_perms, resources_perms_dict or {}, show_all_children),
        fallback=lambda: db_session.rollback(), httpError=HTTPInternalServerError,
        msgOnFail="Failed to format service resources tree",
        content=format_service(service, service_perms, show_private_url=show_private_url)
    )


def format_service_resource_type(resource_type, service_type):
    # type: (Resource, ServiceI) -> JsonBody
    return {
        u'resource_type': resource_type.resource_type_name,
        u'resource_child_allowed': resource_type.child_resource_allowed,
        u'permission_names': service_type.resource_types_permissions[resource_type.resource_type_name],
    }
