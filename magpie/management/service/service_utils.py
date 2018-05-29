from management.group.group_utils import create_group_resource_permission, SERVICES_PHOENIX_ALLOWED
from register import get_twitcher_protected_service_url
from ziggurat_definitions import *
from api_except import *
from services import service_type_dict
from management.resource.resource_utils import (
    get_resource_children,
    format_resource_tree,
    crop_tree_with_permission
)
import models
import os


def format_service(service, permissions=None):
    def fmt_svc(svc, perms):
        return {
            u'public_url': str(get_twitcher_protected_service_url(svc.resource_name)),
            u'service_url': str(svc.url),
            u'service_name': str(svc.resource_name),
            u'service_type': str(svc.type),
            u'resource_id': svc.resource_id,
            u'permission_names': list() if perms is None else perms
        }

    return evaluate_call(
        lambda: fmt_svc(service, permissions),
        httpError=HTTPInternalServerError,
        msgOnFail="Failed to format service",
        content={u'service': repr(service), u'permissions': repr(permissions)}
    )


def format_service_resources(service, db_session, service_perms=None, resources_perms_dict=None, display_all=False):
    service_perms = list() if service_perms is None else service_perms
    resources_perms_dict = dict() if resources_perms_dict is None else resources_perms_dict

    def fmt_svc_res(svc, db, svc_perms, res_perms, show_all):
        tree = get_resource_children(svc, db)
        if not show_all:
            tree, resource_id_list_remain = crop_tree_with_permission(tree, res_perms.keys())

        svc_res = format_service(svc, svc_perms)
        svc_res[u'resources'] = format_resource_tree(tree, resources_perms_dict=res_perms, db_session=db)
        return svc_res

    return evaluate_call(
        lambda: fmt_svc_res(service, db_session, service_perms, resources_perms_dict, display_all),
        fallback=db_session.rollback(), httpError=HTTPInternalServerError,
        msgOnFail="Failed to format service resources tree",
        content=format_service(service)
    )


def get_services_by_type(service_type, db_session):
    verify_param(service_type, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `service_type` value '" + str(service_type) + "' specified")
    services = db_session.query(models.Service).filter(models.Service.type == service_type)
    return services


def add_service_getcapabilities_perms(service, db_session, group_name=None):
    if service.type in SERVICES_PHOENIX_ALLOWED \
    and 'getcapabilities' in service_type_dict[service.type].permission_names:
        if group_name is None:
            group_name = os.getenv('ANONYMOUS_USER')
        group = GroupService.by_group_name(group_name, db_session=db_session)
        perm = ResourceService.perm_by_group_and_perm_name(service.resource_id, group.id,
                                                           u'getcapabilities', db_session)
        if perm is None:  # not set, create it
            create_group_resource_permission(u'getcapabilities', service.resource_id, group.id, db_session)
