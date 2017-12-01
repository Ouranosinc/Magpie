from magpie import *
import models
from models import resource_tree_service
from services import service_type_dict
from resource import resource_type_dict
from api_requests import *
from api_except import *
from register import *
from management.group.group_utils import create_group_resource_permission
from management.service.resource import *


def format_service(service, permissions=None):
    def fmt_svc(svc, perms):
        return {
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


@view_config(route_name='services_type', request_method='GET')
@view_config(route_name='services', request_method='GET')
def get_services_view(request):
    service_type_filter = request.matchdict.get('service_type')  # no check because None/empty is for 'all services'
    json_response = {}
    if not service_type_filter:
        service_types = service_type_dict.keys()
    else:
        verify_param(service_type_filter, paramCompare=service_type_dict.keys(), isIn=True, httpError=HTTPNotAcceptable,
                     msgOnFail="Invalid `service_type` value does not correspond to any of the existing service types",
                     content={u'service_type': str(service_type_filter)}, contentType='application/json')
        service_types = [service_type_filter]

    for service_type in service_types:
        services = get_services_by_type(service_type, db_session=request.db)
        json_response[service_type] = {}
        for service in services:
            json_response[service_type][service.resource_name] = format_service(service)

    return valid_http(httpSuccess=HTTPOk, detail="Get services successful", content={u'services': json_response})


@view_config(route_name='services', request_method='POST')
def register_service(request):
    service_name = get_value_multiformat_post_checked(request, 'service_name')
    service_url = get_value_multiformat_post_checked(request, 'service_url')
    service_type = get_value_multiformat_post_checked(request, 'service_type')
    service_push = str2bool(get_multiformat_post(request, 'service_push'))
    verify_param(service_type, isIn=True, paramCompare=service_type_dict.keys(), httpError=HTTPNotAcceptable,
                 msgOnFail="Specified `service_type` value does not correspond to any of the available types")

    if models.Service.by_service_name(service_name, db_session=request.db):
        verify_param(service_name, notIn=True, httpError=HTTPConflict,
                     paramCompare=[models.Service.by_service_name(service_name, db_session=request.db).resource_name],
                     msgOnFail="Specified `service_name` value '" + str(service_name) + "' already exists")

    service = evaluate_call(lambda: models.Service(resource_name=str(service_name), resource_type=u'service',
                                                   url=str(service_url), type=str(service_type)),
                            fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                            msgOnFail="Service creation for registration failed",
                            content={u'service_name': str(service_name), u'resource_type': u'service',
                                     u'service_url': str(service_url), u'service_type': str(service_type)})

    def add_service_magpie_and_phoenix(svc, svc_push, db):
        db.add(svc)
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED:
            sync_services_phoenix(db.query(models.Service))

    evaluate_call(lambda: add_service_magpie_and_phoenix(service, service_push, request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Service registration forbidden by db", content=format_service(service))
    return valid_http(httpSuccess=HTTPCreated, detail="Service registration to db successful",
                      content=format_service(service))


@view_config(route_name='service', request_method='PUT')
def update_service(request):
    service = get_service_matchdict_checked(request)
    service_push = str2bool(get_multiformat_post(request, 'service_push'))

    def select_update(new_value, old_value):
        return new_value if new_value is not None and not new_value == '' else old_value

    # None/Empty values are accepted in case of unspecified
    svc_name = select_update(get_multiformat_post(request, 'service_name'), service.resource_name)
    svc_url = select_update(get_multiformat_post(request, 'service_url'), service.url)
    verify_param(svc_name == service.resource_name and svc_url == service.url, isEqual=True, paramCompare=True,
                 httpError=HTTPBadRequest, msgOnFail="Current service values are already equal to update values")

    if svc_name != service.resource_name:
        all_svc_names = list()
        for svc_type in service_type_dict:
            for svc in get_services_by_type(svc_type, db_session=request.db):
                all_svc_names.extend(svc.resource_name)
        verify_param(svc_name, notIn=True, paramCompare=all_svc_names, httpError=HTTPConflict,
                     msgOnFail="Specified `service_name` value '" + str(svc_name) + "' already exists")

    def update_service_magpie_and_phoenix(svc, new_name, new_url, svc_push, db):
        svc.resource_name = new_name
        svc.url = new_url
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED \
        and 'getcapabilities' in service_type_dict[svc.type].permission_names:
            # (re)apply getcapabilities to updated service to ensure updated push
            add_service_getcapabilities_perms(svc, db)
            sync_services_phoenix(db.query(models.Service))  # push all services

    old_svc_content = format_service(service)
    err_svc_content = {u'service': old_svc_content, u'new_service_name': svc_name, u'new_service_url': svc_url}
    evaluate_call(lambda: update_service_magpie_and_phoenix(service, svc_name, svc_url, service_push, request.db),
                  fallback=lambda: request.db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Update service failed during value assignment",
                  content=err_svc_content)
    return valid_http(httpSuccess=HTTPOk, detail="Update service successful", content=format_service(service))


@view_config(route_name='service', request_method='GET')
def get_service(request):
    service = get_service_matchdict_checked(request)
    return valid_http(httpSuccess=HTTPOk, detail="Get service successful",
                      content={str(service.resource_name): format_service(service)})


@view_config(route_name='service', request_method='DELETE')
def unregister_service(request):
    service = get_service_matchdict_checked(request)
    service_push = str2bool(get_multiformat_delete(request, 'service_push'))
    svc_content = format_service(service)
    evaluate_call(lambda: resource_tree_service.delete_branch(resource_id=service.resource_id, db_session=request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete service from resource tree failed", content=svc_content)

    def remove_service_magpie_and_phoenix(svc, svc_push, db):
        db.delete(svc)
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED:
            sync_services_phoenix(db.query(models.Service))

    evaluate_call(lambda: remove_service_magpie_and_phoenix(service, service_push, request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete service from db failed", content=svc_content)
    return valid_http(httpSuccess=HTTPOk, detail="Delete service successful")


@view_config(route_name='service_permissions', request_method='GET')
def get_service_permissions(request):
    service = get_service_matchdict_checked(request)
    svc_content = format_service(service)
    svc_perms = evaluate_call(lambda: service_type_dict[service.type].permission_names, fallback=request.db.rollback(),
                              httpError=HTTPNotAcceptable, msgOnFail="Invalid service type specified by service",
                              content=svc_content)
    return valid_http(httpSuccess=HTTPOk, detail="Get service permissions successful",
                      content={u'permission_names': svc_perms})


@view_config(route_name='service_resources', request_method='GET')
def get_service_resources_view(request):
    service = get_service_matchdict_checked(request)
    svc_res_json = format_service_resources(service, db_session=request.db, display_all=True)
    return valid_http(httpSuccess=HTTPOk, detail="Get service resources successful",
                      content={str(service.resource_name): svc_res_json})


@view_config(route_name='service_resources', request_method='POST')
def create_service_direct_resource(request):
    service = get_service_matchdict_checked(request)
    resource_name = get_value_matchdict_checked(request, 'resource_name')
    resource_type = get_value_matchdict_checked(request, 'resource_type')
    parent_id = get_multiformat_post(request, 'parent_id')  # no check because None/empty is allowed
    if not parent_id:
        parent_id = service.resource_id
    return create_resource(resource_name, resource_type, parent_id=parent_id, db_session=request.db)


@view_config(route_name='resources', request_method='GET')
def get_resources_view(request):
    res_json = {}
    for svc_type in service_type_dict.keys():
        services = get_services_by_type(svc_type, db_session=request.db)
        res_json[svc_type] = {}
        for svc in services:
            res_json[svc_type][svc.resource_name] = format_service_resources(svc, request.db, display_all=True)
    res_json = {u'resource_types': resource_type_dict.keys(), u'resources': res_json}
    return valid_http(httpSuccess=HTTPOk, detail="Get resources successful", content=res_json)


@view_config(route_name='service_type_resource_types', request_method='GET')
def get_service_type_resource_types(request):
    service_type = get_value_matchdict_checked(request, 'service_type')
    verify_param(service_type, paramCompare=service_type_dict.keys(), isIn=True, httpError=HTTPNotFound,
                 msgOnFail="Invalid `service_type` does not exist to obtain its resource types")
    resource_types = evaluate_call(lambda: service_type_dict[service_type].resource_types,
                                   httpError=HTTPForbidden, content={u'service_type': str(service_type)},
                                   msgOnFail="Failed to obtain resource types for specified service type")
    return valid_http(httpSuccess=HTTPOk, detail="Get service type resource types successful",
                      content={u'resource_types': resource_types})
