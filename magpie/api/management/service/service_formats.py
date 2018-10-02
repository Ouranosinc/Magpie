from magpie.register import get_twitcher_protected_service_url
from magpie.services import service_type_dict
from magpie.definitions.pyramid_definitions import *
from magpie.api.api_except import evaluate_call
from magpie.api.management.resource.resource_utils import crop_tree_with_permission
from magpie.api.management.resource.resource_formats import get_resource_children, format_resource_tree


def format_service(service, permissions=None):
    def fmt_svc(svc, perms):
        return {
            u'public_url': str(get_twitcher_protected_service_url(svc.resource_name)),
            u'service_url': str(svc.url),
            u'service_name': str(svc.resource_name),
            u'service_type': str(svc.type),
            u'service_sync_type': svc.sync_type,
            u'resource_id': svc.resource_id,
            u'permission_names': sorted(service_type_dict[svc.type].permission_names if perms is None else perms)
        }

    return evaluate_call(
        lambda: fmt_svc(service, permissions),
        httpError=HTTPInternalServerError,
        msgOnFail="Failed to format service.",
        content={u'service': repr(service), u'permissions': repr(permissions)}
    )


def format_service_resources(service, db_session, service_perms=None, resources_perms_dict=None, display_all=False):
    def fmt_svc_res(svc, db, svc_perms, res_perms, show_all):
        tree = get_resource_children(svc, db)
        if not show_all:
            tree, resource_id_list_remain = crop_tree_with_permission(tree, res_perms.keys())

        svc_perms = service_type_dict[svc.type].permission_names if svc_perms is None else svc_perms
        svc_res = format_service(svc, svc_perms)
        svc_res[u'resources'] = format_resource_tree(tree, resources_perms_dict=res_perms, db_session=db)
        return svc_res

    return evaluate_call(
        lambda: fmt_svc_res(service, db_session, service_perms, resources_perms_dict, display_all),
        fallback=db_session.rollback(), httpError=HTTPInternalServerError,
        msgOnFail="Failed to format service resources tree",
        content=format_service(service, service_perms)
    )
