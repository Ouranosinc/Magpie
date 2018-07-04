from api.management.resource.resource_utils import create_resource, delete_resource
from api.management.service.service_formats import *
from api.management.service.service_utils import *
from api.api_requests import *
from api.api_rest_schemas import *
from definitions.pyramid_definitions import view_config
from common import str2bool
from register import sync_services_phoenix
from models import resource_tree_service
from services import service_type_dict


@ServiceTypesAPI.get(tags=[ServiceTag], response_schemas={
    '200': Services_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '406': Services_GET_NotAcceptableResponseSchema(),
})
@view_config(route_name=ServiceTypesAPI.name, request_method='GET')
def get_services_by_type_view(request):
    return get_services_runner(request)


@ServicesAPI.get(tags=[ServiceTag], response_schemas={
    '200': Services_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '406': Services_GET_NotAcceptableResponseSchema(),
})
@view_config(route_name=ServicesAPI.name, request_method='GET')
def get_services_view(request):
    """List all registered services."""
    return get_services_runner(request)


def get_services_runner(request):
    service_type_filter = request.matchdict.get('service_type')  # no check because None/empty is for 'all services'
    json_response = {}
    if not service_type_filter:
        service_types = service_type_dict.keys()
    else:
        verify_param(service_type_filter, paramCompare=service_type_dict.keys(), isIn=True, httpError=HTTPNotAcceptable,
                     msgOnFail=Services_GET_NotAcceptableResponseSchema.description,
                     content={u'service_type': str(service_type_filter)}, contentType='application/json')
        service_types = [service_type_filter]

    for service_type in service_types:
        services = get_services_by_type(service_type, db_session=request.db)
        json_response[service_type] = {}
        for service in services:
            json_response[service_type][service.resource_name] = format_service(service)

    return valid_http(httpSuccess=HTTPOk, detail=Services_GET_OkResponseSchema.description,
                      content={u'services': json_response})


@ServicesAPI.post(schema=Services_POST_RequestBodySchema(), tags=[ServiceTag], response_schemas={
    '201': Services_POST_CreatedResponseSchema(),
    '400': Services_POST_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Services_POST_ForbiddenResponseSchema(),
    '409': Services_POST_ConflictResponseSchema(),
})
@view_config(route_name=ServicesAPI.name, request_method='POST')
def register_service(request):
    """Registers a new service."""
    service_name = get_value_multiformat_post_checked(request, 'service_name')
    service_url = get_value_multiformat_post_checked(request, 'service_url')
    service_type = get_value_multiformat_post_checked(request, 'service_type')
    service_push = str2bool(get_multiformat_post(request, 'service_push'))
    verify_param(service_type, isIn=True, paramCompare=service_type_dict.keys(), httpError=HTTPBadRequest,
                 msgOnFail=Services_POST_BadRequestResponseSchema.description)

    if models.Service.by_service_name(service_name, db_session=request.db):
        verify_param(service_name, notIn=True, httpError=HTTPConflict,
                     paramCompare=[models.Service.by_service_name(service_name, db_session=request.db).resource_name],
                     msgOnFail=Services_POST_ConflictResponseSchema.description,
                     content={u'service_name': str(service_name)})

    service = evaluate_call(lambda: models.Service(resource_name=str(service_name), resource_type=u'service',
                                                   url=str(service_url), type=str(service_type)),
                            fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                            msgOnFail="Service creation for registration failed.",
                            content={u'service_name': str(service_name), u'resource_type': u'service',
                                     u'service_url': str(service_url), u'service_type': str(service_type)})

    def add_service_magpie_and_phoenix(svc, svc_push, db):
        db.add(svc)
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED:
            sync_services_phoenix(db.query(models.Service))

    evaluate_call(lambda: add_service_magpie_and_phoenix(service, service_push, request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail=Services_POST_ForbiddenResponseSchema.description, content=format_service(service))
    return valid_http(httpSuccess=HTTPCreated, detail=Services_POST_CreatedResponseSchema.description,
                      content={u'service': format_service(service)})


@ServiceAPI.put(schema=Service_PUT_RequestBodySchema(), tags=[ServiceTag], response_schemas={
    '200': Service_PUT_OkResponseSchema(),
    '400': Service_PUT_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_PUT_ForbiddenResponseSchema(),
    '409': Service_PUT_ConflictResponseSchema(),
})
@view_config(route_name=ServiceAPI.name, request_method='PUT')
def update_service(request):
    """Update a service information."""
    service = get_service_matchdict_checked(request)
    service_push = str2bool(get_multiformat_post(request, 'service_push', default=False))

    def select_update(new_value, old_value):
        return new_value if new_value is not None and not new_value == '' else old_value

    # None/Empty values are accepted in case of unspecified
    svc_name = select_update(get_multiformat_post(request, 'service_name'), service.resource_name)
    svc_url = select_update(get_multiformat_post(request, 'service_url'), service.url)
    verify_param(svc_name == service.resource_name and svc_url == service.url, notEqual=True, paramCompare=True,
                 httpError=HTTPBadRequest, msgOnFail=Service_PUT_BadRequestResponseSchema.description)

    if svc_name != service.resource_name:
        all_svc_names = list()
        for svc_type in service_type_dict:
            for svc in get_services_by_type(svc_type, db_session=request.db):
                all_svc_names.extend(svc.resource_name)
        verify_param(svc_name, notIn=True, paramCompare=all_svc_names, httpError=HTTPConflict,
                     msgOnFail=Service_PUT_ConflictResponseSchema.description,
                     content={u'service_name': str(svc_name)})

    def update_service_magpie_and_phoenix(svc, new_name, new_url, svc_push, db_session):
        svc.resource_name = new_name
        svc.url = new_url
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED \
        and 'getcapabilities' in service_type_dict[svc.type].permission_names:
            # (re)apply getcapabilities to updated service to ensure updated push
            add_service_getcapabilities_perms(svc, db_session)
            sync_services_phoenix(db_session.query(models.Service))  # push all services

    old_svc_content = format_service(service)
    err_svc_content = {u'service': old_svc_content, u'new_service_name': svc_name, u'new_service_url': svc_url}
    evaluate_call(lambda: update_service_magpie_and_phoenix(service, svc_name, svc_url, service_push, request.db),
                  fallback=lambda: request.db.rollback(),
                  httpError=HTTPForbidden, msgOnFail=Service_PUT_ForbiddenResponseSchema.description,
                  content=err_svc_content)
    return valid_http(httpSuccess=HTTPOk, detail=Service_PUT_OkResponseSchema.description,
                      content={u'service': format_service(service)})


@ServiceAPI.get(tags=[ServiceTag], response_schemas={
    '200': Service_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
})
@view_config(route_name=ServiceAPI.name, request_method='GET')
def get_service(request):
    """Get a service information."""
    service = get_service_matchdict_checked(request)
    return valid_http(httpSuccess=HTTPOk, detail=Service_GET_OkResponseSchema.name,
                      content={service.resource_name: format_service(service)})


@ServiceAPI.delete(schema=Service_DELETE_RequestSchema(), tags=[ServiceTag], response_schemas={
    '200': Service_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_DELETE_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
})
@view_config(route_name=ServiceAPI.name, request_method='DELETE')
def unregister_service(request):
    """Unregister a service."""
    service = get_service_matchdict_checked(request)
    service_push = str2bool(get_multiformat_delete(request, 'service_push', default=False))
    svc_content = format_service(service)
    evaluate_call(lambda: resource_tree_service.delete_branch(resource_id=service.resource_id, db_session=request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete service from resource tree failed.", content=svc_content)

    def remove_service_magpie_and_phoenix(svc, svc_push, db_session):
        db_session.delete(svc)
        if svc_push and svc.type in SERVICES_PHOENIX_ALLOWED:
            sync_services_phoenix(db_session.query(models.Service))

    evaluate_call(lambda: remove_service_magpie_and_phoenix(service, service_push, request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail=Service_DELETE_ForbiddenResponseSchema.description, content=svc_content)
    return valid_http(httpSuccess=HTTPOk, detail=Service_DELETE_OkResponseSchema.description)


@ServicePermissionsAPI.get(tags=[ServiceTag], response_schemas={
    '200': ServicePermissions_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
    '406': ServicePermissions_GET_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ServicePermissionsAPI.name, request_method='GET')
def get_service_permissions(request):
    """List all applicable permissions for a service."""
    service = get_service_matchdict_checked(request)
    svc_content = format_service(service)
    svc_perms = evaluate_call(lambda: service_type_dict[service.type].permission_names,
                              fallback=request.db.rollback(), httpError=HTTPNotAcceptable, content=svc_content,
                              msgOnFail=ServicePermissions_GET_NotAcceptableResponseSchema.description)
    return valid_http(httpSuccess=HTTPOk, detail=ServicePermissions_GET_OkResponseSchema.description,
                      content={u'permission_names': svc_perms})


@ServiceResourceAPI.delete(schema=ServiceResource_DELETE_RequestSchema(), tags=[ServiceTag], response_schemas={
    '200': ServiceResource_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': ServiceResource_DELETE_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ServiceResourceAPI.name, request_method='DELETE')
def delete_service_resource_view(request):
    """Unregister a resource."""
    return delete_resource(request)


@ServiceResourcesAPI.get(tags=[ServiceTag], response_schemas={
    '200': ServiceResources_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ServiceResourcesAPI.name, request_method='GET')
def get_service_resources_view(request):
    """List all resources registered under a service."""
    service = get_service_matchdict_checked(request)
    svc_res_json = format_service_resources(service, db_session=request.db, display_all=True)
    return valid_http(httpSuccess=HTTPOk, detail=ServiceResources_GET_OkResponseSchema.description,
                      content={str(service.resource_name): svc_res_json})


@ServiceResourcesAPI.post(schema=ServiceResources_POST_RequestBodySchema, tags=[ServiceTag], response_schemas={
    '200': ServiceResources_POST_OkResponseSchema(),
    '400': ServiceResources_POST_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': ServiceResources_POST_ForbiddenResponseSchema(),
    '404': ServiceResources_POST_NotFoundResponseSchema(),
    '409': ServiceResources_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ServiceResourcesAPI.name, request_method='POST')
def create_service_direct_resource(request):
    """Register a new resource directly under a service."""
    service = get_service_matchdict_checked(request)
    resource_name = get_multiformat_post(request, 'resource_name')
    resource_type = get_multiformat_post(request, 'resource_type')
    parent_id = get_multiformat_post(request, 'parent_id')  # no check because None/empty is allowed
    if not parent_id:
        parent_id = service.resource_id
    return create_resource(resource_name, resource_type, parent_id=parent_id, db_session=request.db)


@ServiceResourceTypesAPI.get(tags=[ServiceTag], response_schemas={
    '200': ServiceResourceTypes_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': ServiceResourceTypes_GET_ForbiddenResponseSchema(),
    '404': ServiceResourceTypes_GET_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ServiceResourceTypesAPI.name, request_method='GET')
def get_service_type_resource_types(request):
    """List all resources under a specific service type."""
    service_type = get_value_matchdict_checked(request, 'service_type')
    verify_param(service_type, paramCompare=service_type_dict.keys(), isIn=True, httpError=HTTPNotFound,
                 msgOnFail=ServiceResourceTypes_GET_NotFoundResponseSchema.description)
    resource_types = evaluate_call(lambda: service_type_dict[service_type].resource_types,
                                   httpError=HTTPForbidden, content={u'service_type': str(service_type)},
                                   msgOnFail=ServiceResourceTypes_GET_ForbiddenResponseSchema.description)
    return valid_http(httpSuccess=HTTPOk, detail=ServiceResourceTypes_GET_OkResponseSchema.description,
                      content={u'resource_types': resource_types})
