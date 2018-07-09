from api.api_requests import *
from api.management.service.service_utils import get_services_by_type
from api.management.service.service_formats import format_service_resources
from api.management.resource.resource_utils import *
from api.management.resource.resource_formats import *
from definitions.pyramid_definitions import view_config
from common import str2bool
from register import sync_services_phoenix
from services import service_type_dict


@ResourcesAPI.get(tags=[ResourcesTag], response_schemas={
    '200': Resources_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '500': Resource_GET_InternalServerErrorResponseSchema()
})
@view_config(route_name=ResourcesAPI.name, request_method='GET')
def get_resources_view(request):
    """List all registered resources."""
    res_json = {}
    for svc_type in service_type_dict.keys():
        services = get_services_by_type(svc_type, db_session=request.db)
        res_json[svc_type] = {}
        for svc in services:
            res_json[svc_type][svc.resource_name] = format_service_resources(svc, request.db, display_all=True)
    res_json = {u'resources': res_json}
    return valid_http(httpSuccess=HTTPOk, detail=Resources_GET_OkResponseSchema.description, content=res_json)


@ResourceAPI.get(tags=[ResourcesTag], response_schemas={
    '200': Resource_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Resource_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
    '500': Resource_GET_InternalServerErrorResponseSchema()
})
@view_config(route_name=ResourceAPI.name, request_method='GET')
def get_resource_view(request):
    """Get resource information."""
    resource = get_resource_matchdict_checked(request)
    res_json = evaluate_call(lambda: format_resource_with_children(resource, db_session=request.db),
                             fallback=lambda: request.db.rollback(), httpError=HTTPInternalServerError,
                             msgOnFail=Resource_GET_InternalServerErrorResponseSchema.description,
                             content={u'resource': format_resource(resource, basic_info=True)})
    return valid_http(httpSuccess=HTTPOk, detail=Resource_GET_OkResponseSchema.description,
                      content={resource.resource_id: res_json})


@ResourcesAPI.post(schema=Resources_POST_RequestBodySchema, tags=[ResourcesTag], response_schemas={
    '200': Resources_POST_OkResponseSchema(),
    '400': Resources_POST_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Resources_POST_ForbiddenResponseSchema(),
    '404': Resources_POST_NotFoundResponseSchema(),
    '409': Resources_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ResourcesAPI.name, request_method='POST')
def create_resource_view(request):
    """Register a new resource."""
    resource_name = get_value_multiformat_post_checked(request, 'resource_name')
    resource_type = get_value_multiformat_post_checked(request, 'resource_type')
    parent_id = get_value_multiformat_post_checked(request, 'parent_id')
    return create_resource(resource_name, resource_type, parent_id, request.db)


@ResourceAPI.delete(schema=ServiceResource_DELETE_RequestSchema(), tags=[ResourcesTag], response_schemas={
    '200': Resource_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Resource_DELETE_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ResourceAPI.name, request_method='DELETE')
def delete_resource_view(request):
    """Unregister a resource."""
    return delete_resource(request)


@ResourceAPI.put(schema=Resource_PUT_RequestSchema(), tags=[ResourcesTag], response_schemas={
    '200': Resource_PUT_OkResponseSchema(),
    '403': Resource_PUT_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ResourceAPI.name, request_method='PUT')
def update_resource(request):
    """Update a resource information."""
    resource = get_resource_matchdict_checked(request, 'resource_id')
    service_push = str2bool(get_multiformat_post(request, 'service_push'))
    res_old_name = resource.resource_name
    res_new_name = get_value_multiformat_post_checked(request, 'resource_name')

    def rename_service_magpie_and_phoenix(res, new_name, svc_push, db):
        if res.resource_type != 'service':
            svc_push = False
        res.resource_name = new_name
        if svc_push:
            sync_services_phoenix(db.query(models.Service))

    evaluate_call(lambda: rename_service_magpie_and_phoenix(resource, res_new_name, service_push, request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail=Resource_PUT_ForbiddenResponseSchema.description,
                  content={u'resource_id': resource.resource_id, u'resource_name': resource.resource_name,
                           u'old_resource_name': res_old_name, u'new_resource_name': res_new_name})
    return valid_http(httpSuccess=HTTPOk, detail=Resource_PUT_OkResponseSchema.description,
                      content={u'resource_id': resource.resource_id, u'resource_name': resource.resource_name,
                               u'old_resource_name': res_old_name, u'new_resource_name': res_new_name})


@ResourcePermissionsAPI.get(tags=[ResourcesTag], response_schemas={
    '200': ResourcePermissions_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Resource_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': ResourcePermissions_GET_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
})
@view_config(route_name=ResourcePermissionsAPI.name, request_method='GET')
def get_resource_permissions_view(request):
    """List all applicable permissions for a resource."""
    resource = get_resource_matchdict_checked(request, 'resource_id')
    res_perm = evaluate_call(lambda: get_resource_permissions(resource, db_session=request.db),
                             fallback=lambda: request.db.rollback(), httpError=HTTPNotAcceptable,
                             msgOnFail=ResourcePermissions_GET_NotAcceptableResponseSchema.description,
                             content={u'resource': format_resource(resource, basic_info=True)})
    return valid_http(httpSuccess=HTTPOk, detail=ResourcePermissions_GET_OkResponseSchema.description,
                      content={u'permission_names': res_perm})
