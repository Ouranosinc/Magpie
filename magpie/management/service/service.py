from magpie import *
import models
from models import resource_tree_service
from services import service_type_dict
from resource import resource_type_dict
from api_requests import *
from api_except import *
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


@view_config(route_name='services_type', request_method='GET')
@view_config(route_name='services', request_method='GET')
def get_services_view(request):
    service_type = request.matchdict.get('service_type')    # can be 'None' for 'all services'
    json_response = {}
    if not service_type:
        service_types = service_type_dict.keys()
    else:
        verify_param(service_type, paramCompare=service_type_dict.keys(), isIn=True, httpError=HTTPNotAcceptable,
                     msgOnFail="Invalid `service_type` value '" + str(service_type) +
                               "' does not correspond to any of the existing service types")
        service_types = [service_type]

    for service_type in service_types:
        services = get_services_by_type(service_type, db_session=request.db)
        json_response[service_type] = {}
        for service in services:
            json_response[service_type][service.resource_name] = format_service(service)

    return valid_http(httpSuccess=HTTPOk, detail="Get services successful", content={u'services': json_response})


@view_config(route_name='services', request_method='POST')
def register_service(request):
    service_name = get_value_matchdict_checked(request, 'service_name')
    service_url = get_value_matchdict_checked(request, 'service_url')
    service_type = get_value_matchdict_checked(request, 'service_type')
    verify_param(service_type, isIn=True, httpError=HTTPNotAcceptable, paramCompare=service_type_dict.keys(),
                 msgOnFail="Specified `service_type` value does not correspond to any of the available types")
    verify_param(service_name, notIn=True, httpError=HTTPConflict,
                 paramCompare=[models.Service.by_service_name(service_name, db_session=request.db)],
                 msgOnFail="Specified `service_name` value '" + str(service_name) + "' already exists")

    service = evaluate_call(lambda: models.Service(resource_name=str(service_name), resource_type=u'service',
                                                   url=str(service_url), type=str(service_type)),
                            fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                            msgOnFail="Service creation for registration failed",
                            content={u'service_name': str(service_name), u'resource_type': u'service',
                                     u'service_url': str(service_url), u'service_type': str(service_type)})
    evaluate_call(lambda: request.db.add(service), fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Service registration forbidden by db", content=format_service(service))
    return valid_http(httpSuccess=HTTPCreated, detail="Service registration to db successful",
                      content=format_service(service))


@view_config(route_name='service', request_method='GET')
def get_service(request):
    service = get_service_matchdict_checked(request)
    return valid_http(httpSuccess=HTTPOk, detail="Get service successful", content=format_service(service))


@view_config(route_name='service', request_method='DELETE')
def unregister_service(request):
    service = get_service_matchdict_checked(request)
    svc_content = format_service(service)
    evaluate_call(lambda: resource_tree_service.delete_branch(resource_id=service.resource_id, db_session=request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete service from resource tree failed", content=svc_content)
    evaluate_call(lambda: request.db.delete(service), fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete service from db failed", content=svc_content)
    return valid_http(httpSuccess=HTTPOk, detail="Delete service successful", content=svc_content)


@view_config(route_name='service', request_method='PUT')
def update_service(request):
    service = get_service_matchdict_checked(request)
    service_url = get_value_matchdict_checked(request, 'service_url')
    svc_content = format_service(service)

    def set_url(svc, url):
        svc.url = url
    evaluate_call(lambda: set_url(service, service_url), fallback=lambda: request.db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Update service failed during URL assignment",
                  content={u'service': svc_content, u'service_url': str(service_url)})
    return valid_http(httpSuccess=HTTPOk, detail="Update service successful", content=svc_content)


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
    parent_id = get_multiformat_post(request, 'parent_id')
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
