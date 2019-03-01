from magpie.api.management.resource.resource_utils import create_resource, delete_resource
from magpie.api.management.service import service_formats as sf, service_utils as su
from magpie.api import api_requests as ar, api_except as ax, api_rest_schemas as s
from magpie.definitions.pyramid_definitions import (
    view_config,
    HTTPOk,
    HTTPBadRequest,
    HTTPForbidden,
    HTTPNotFound,
    HTTPNotAcceptable,
    HTTPConflict,
)
from magpie.common import str2bool, JSON_TYPE
from magpie.register import sync_services_phoenix, SERVICES_PHOENIX_ALLOWED
from magpie.services import service_type_dict
from magpie import models


# noinspection PyUnusedLocal
@s.ServiceTypesAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceTypes_GET_responses)
@view_config(route_name=s.ServiceTypesAPI.name, request_method='GET')
def get_service_types_view(request):
    """List all available service types."""
    return ax.valid_http(httpSuccess=HTTPOk, content={u'service_types': list(sorted(service_type_dict.keys()))},
                         detail=s.ServiceTypes_GET_OkResponseSchema.description)


@s.ServiceTypeAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceType_GET_responses)
@view_config(route_name=s.ServiceTypeAPI.name, request_method='GET')
def get_services_by_type_view(request):
    """List all registered services from a specific type."""
    return get_services_runner(request)


@s.ServicesAPI.get(tags=[s.ServicesTag], response_schemas=s.Services_GET_responses)
@view_config(route_name=s.ServicesAPI.name, request_method='GET')
def get_services_view(request):
    """List all registered services."""
    return get_services_runner(request)


def get_services_runner(request):
    service_type_filter = request.matchdict.get('service_type')  # no check because None/empty is for 'all services'
    json_response = {}
    if not service_type_filter:
        service_types = service_type_dict.keys()
    else:
        ax.verify_param(service_type_filter, paramCompare=service_type_dict.keys(), isIn=True,
                        httpError=HTTPNotAcceptable, msgOnFail=s.Services_GET_NotAcceptableResponseSchema.description,
                        content={u'service_type': str(service_type_filter)}, contentType=JSON_TYPE)
        service_types = [service_type_filter]

    for service_type in service_types:
        services = su.get_services_by_type(service_type, db_session=request.db)
        json_response[service_type] = {}
        for service in services:
            json_response[service_type][service.resource_name] = sf.format_service(service, show_private_url=True)

    return ax.valid_http(httpSuccess=HTTPOk, content={u'services': json_response},
                         detail=s.Services_GET_OkResponseSchema.description)


@s.ServicesAPI.post(schema=s.Services_POST_RequestBodySchema(), tags=[s.ServicesTag],
                    response_schemas=s.Services_POST_responses)
@view_config(route_name=s.ServicesAPI.name, request_method='POST')
def register_service_view(request):
    """Registers a new service."""
    service_name = ar.get_value_multiformat_post_checked(request, 'service_name')
    service_url = ar.get_value_multiformat_post_checked(request, 'service_url')
    service_type = ar.get_value_multiformat_post_checked(request, 'service_type')
    service_push = str2bool(ar.get_multiformat_post(request, 'service_push'))
    ax.verify_param(service_type, isIn=True, paramCompare=service_type_dict.keys(),
                    httpError=HTTPBadRequest, msgOnFail=s.Services_POST_BadRequestResponseSchema.description)
    ax.verify_param(models.Service.by_service_name(service_name, db_session=request.db), isNone=True,
                    httpError=HTTPConflict, msgOnFail=s.Services_POST_ConflictResponseSchema.description,
                    content={u'service_name': str(service_name)}, paramName=u'service_name')
    return su.create_service(service_name, service_type, service_url, service_push, db_session=request.db)


@s.ServiceAPI.put(schema=s.Service_PUT_RequestBodySchema(), tags=[s.ServicesTag],
                  response_schemas=s.Service_PUT_responses)
@view_config(route_name=s.ServiceAPI.name, request_method='PUT')
def update_service_view(request):
    """Update a service information."""
    service = ar.get_service_matchdict_checked(request)
    service_push = str2bool(ar.get_multiformat_post(request, 'service_push', default=False))

    def select_update(new_value, old_value):
        return new_value if new_value is not None and not new_value == '' else old_value

    # None/Empty values are accepted in case of unspecified
    svc_name = select_update(ar.get_multiformat_post(request, 'service_name'), service.resource_name)
    svc_url = select_update(ar.get_multiformat_post(request, 'service_url'), service.url)
    ax.verify_param(svc_name, paramCompare='types', notEqual=True,
                    paramName='service_name', httpError=HTTPBadRequest,
                    msgOnFail=s.Service_PUT_BadRequestResponseSchema_ReservedKeyword.description)
    ax.verify_param(svc_name == service.resource_name and svc_url == service.url, notEqual=True,
                    paramCompare=True, paramName="service_name/service_url",
                    httpError=HTTPBadRequest, msgOnFail=s.Service_PUT_BadRequestResponseSchema.description)

    if svc_name != service.resource_name:
        all_svc_names = list()
        for svc_type in service_type_dict:
            for svc in su.get_services_by_type(svc_type, db_session=request.db):
                all_svc_names.append(svc.resource_name)
        ax.verify_param(svc_name, notIn=True, paramCompare=all_svc_names, httpError=HTTPConflict,
                        msgOnFail=s.Service_PUT_ConflictResponseSchema.description,
                        content={u'service_name': str(svc_name)})

    def update_service_magpie_and_phoenix(_svc, new_name, new_url, svc_push, db_session):
        _svc.resource_name = new_name
        _svc.url = new_url
        has_getcap = 'getcapabilities' in service_type_dict[_svc.type].permission_names
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED and has_getcap:
            # (re)apply getcapabilities to updated service to ensure updated push
            su.add_service_getcapabilities_perms(_svc, db_session)
            sync_services_phoenix(db_session.query(models.Service))  # push all services

    old_svc_content = sf.format_service(service, show_private_url=True)
    err_svc_content = {u'service': old_svc_content, u'new_service_name': svc_name, u'new_service_url': svc_url}
    ax.evaluate_call(lambda: update_service_magpie_and_phoenix(service, svc_name, svc_url, service_push, request.db),
                     fallback=lambda: request.db.rollback(),
                     httpError=HTTPForbidden, msgOnFail=s.Service_PUT_ForbiddenResponseSchema.description,
                     content=err_svc_content)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.Service_PUT_OkResponseSchema.description,
                         content={u'service': sf.format_service(service, show_private_url=True)})


@s.ServiceAPI.get(tags=[s.ServicesTag], response_schemas=s.Service_GET_responses)
@view_config(route_name=s.ServiceAPI.name, request_method='GET')
def get_service_view(request):
    """Get a service information."""
    service = ar.get_service_matchdict_checked(request)
    service_info = sf.format_service(service, show_private_url=True, show_resources_allowed=True)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.Service_GET_OkResponseSchema.description,
                         content={u'service': service_info})


@s.ServiceAPI.delete(schema=s.Service_DELETE_RequestSchema(), tags=[s.ServicesTag],
                     response_schemas=s.Service_DELETE_responses)
@view_config(route_name=s.ServiceAPI.name, request_method='DELETE')
def unregister_service_view(request):
    """Unregister a service."""
    service = ar.get_service_matchdict_checked(request)
    service_push = str2bool(ar.get_multiformat_delete(request, 'service_push', default=False))
    svc_content = sf.format_service(service, show_private_url=True)
    svc_res_id = service.resource_id
    ax.evaluate_call(lambda: models.resource_tree_service.delete_branch(resource_id=svc_res_id, db_session=request.db),
                     fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                     msgOnFail="Delete service from resource tree failed.", content=svc_content)

    def remove_service_magpie_and_phoenix(svc, svc_push, db_session):
        db_session.delete(svc)
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED:
            sync_services_phoenix(db_session.query(models.Service))

    ax.evaluate_call(lambda: remove_service_magpie_and_phoenix(service, service_push, request.db),
                     fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                     msgOnFail=s.Service_DELETE_ForbiddenResponseSchema.description, content=svc_content)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.Service_DELETE_OkResponseSchema.description)


@s.ServicePermissionsAPI.get(tags=[s.ServicesTag], response_schemas=s.ServicePermissions_GET_responses)
@view_config(route_name=s.ServicePermissionsAPI.name, request_method='GET')
def get_service_permissions_view(request):
    """List all applicable permissions for a service."""
    service = ar.get_service_matchdict_checked(request)
    svc_content = sf.format_service(service, show_private_url=True)
    svc_perms = ax.evaluate_call(lambda: service_type_dict[service.type].permission_names,
                                 fallback=request.db.rollback(), httpError=HTTPNotAcceptable, content=svc_content,
                                 msgOnFail=s.ServicePermissions_GET_NotAcceptableResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.ServicePermissions_GET_OkResponseSchema.description,
                         content={u'permission_names': sorted(svc_perms)})


@s.ServiceResourceAPI.delete(schema=s.ServiceResource_DELETE_RequestSchema(), tags=[s.ServicesTag],
                             response_schemas=s.ServiceResource_DELETE_responses)
@view_config(route_name=s.ServiceResourceAPI.name, request_method='DELETE')
def delete_service_resource_view(request):
    """Unregister a resource."""
    return delete_resource(request)


@s.ServiceResourcesAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceResources_GET_responses)
@view_config(route_name=s.ServiceResourcesAPI.name, request_method='GET')
def get_service_resources_view(request):
    """List all resources registered under a service."""
    service = ar.get_service_matchdict_checked(request)
    svc_res_json = sf.format_service_resources(service, db_session=request.db,
                                               show_all_children=True, show_private_url=True)
    return ax.valid_http(httpSuccess=HTTPOk, content={svc_res_json['service_name']: svc_res_json},
                         detail=s.ServiceResources_GET_OkResponseSchema.description)


@s.ServiceResourcesAPI.post(schema=s.ServiceResources_POST_RequestSchema, tags=[s.ServicesTag],
                            response_schemas=s.ServiceResources_POST_responses)
@view_config(route_name=s.ServiceResourcesAPI.name, request_method='POST')
def create_service_direct_resource_view(request):
    """Register a new resource directly under a service."""
    service = ar.get_service_matchdict_checked(request)
    resource_name = ar.get_multiformat_post(request, 'resource_name')
    resource_display_name = ar.get_multiformat_post(request, 'resource_display_name', default=resource_name)
    resource_type = ar.get_multiformat_post(request, 'resource_type')
    parent_id = ar.get_multiformat_post(request, 'parent_id')  # no check because None/empty is allowed
    if not parent_id:
        parent_id = service.resource_id
    return create_resource(resource_name, resource_display_name, resource_type,
                           parent_id=parent_id, db_session=request.db)


@s.ServiceTypeResourcesAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceTypeResources_GET_responses)
@view_config(route_name=s.ServiceTypeResourcesAPI.name, request_method='GET')
def get_service_type_resources_view(request):
    """List details of resource types supported under a specific service type."""

    def _get_resource_types_info(res_type_names):
        res_type_classes = [r for rt, r in models.resource_type_dict.items() if rt in res_type_names]
        return [sf.format_service_resource_type(r, service_type_dict[service_type]) for r in res_type_classes]

    service_type = ar.get_value_matchdict_checked(request, 'service_type')
    ax.verify_param(service_type, paramCompare=service_type_dict.keys(), isIn=True, httpError=HTTPNotFound,
                    msgOnFail=s.ServiceTypeResources_GET_NotFoundResponseSchema.description)
    resource_types_names = ax.evaluate_call(
        lambda: service_type_dict[service_type].resource_types,
        httpError=HTTPForbidden, content={u'service_type': str(service_type)},
        msgOnFail=s.ServiceTypeResourceTypes_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.ServiceTypeResourceTypes_GET_OkResponseSchema.description,
                         content={u'resource_types': _get_resource_types_info(resource_types_names)})


@s.ServiceTypeResourceTypesAPI.get(tags=[s.ServicesTag], response_schemas=s.ServiceTypeResourceTypes_GET_responses)
@view_config(route_name=s.ServiceTypeResourceTypesAPI.name, request_method='GET')
def get_service_type_resource_types_view(request):
    """List all resource types supported under a specific service type."""
    service_type = ar.get_value_matchdict_checked(request, 'service_type')
    ax.verify_param(service_type, paramCompare=service_type_dict.keys(), isIn=True, httpError=HTTPNotFound,
                    msgOnFail=s.ServiceTypeResourceTypes_GET_NotFoundResponseSchema.description)
    resource_types = ax.evaluate_call(lambda: service_type_dict[service_type].resource_types,
                                      httpError=HTTPForbidden, content={u'service_type': str(service_type)},
                                      msgOnFail=s.ServiceTypeResourceTypes_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.ServiceTypeResourceTypes_GET_OkResponseSchema.description,
                         content={u'resource_types': resource_types})
