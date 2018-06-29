from api.management.service.service_utils import get_services_by_type
from api.management.service.service_formats import format_service_resources
from api.management.resource.resource_utils import *
from api.management.resource.resource_formats import *
from definitions.pyramid_definitions import view_config
from common import str2bool
from register import sync_services_phoenix
from services import service_type_dict


@view_config(route_name='resources', request_method='GET')
def get_resources_view(request):
    res_json = {}
    for svc_type in service_type_dict.keys():
        services = get_services_by_type(svc_type, db_session=request.db)
        res_json[svc_type] = {}
        for svc in services:
            res_json[svc_type][svc.resource_name] = format_service_resources(svc, request.db, display_all=True)
    res_json = {u'resources': res_json}
    return valid_http(httpSuccess=HTTPOk, detail="Get resources successful", content=res_json)


@view_config(route_name=ResourceAPI.name, request_method='GET')
def get_resource_view(request):
    resource = get_resource_matchdict_checked(request)
    res_json = evaluate_call(lambda: format_resource_with_children(resource, db_session=request.db),
                             fallback=lambda: request.db.rollback(), httpError=HTTPInternalServerError,
                             msgOnFail="Failed building resource children json formatted tree",
                             content=format_resource(resource, basic_info=True))
    return valid_http(httpSuccess=HTTPOk, detail="Get resource successful", content={resource.resource_id: res_json})


@view_config(route_name=ResourcesAPI.name, request_method='POST')
def create_resource_view(request):
    resource_name = get_value_multiformat_post_checked(request, 'resource_name')
    resource_type = get_value_multiformat_post_checked(request, 'resource_type')
    parent_id = get_value_multiformat_post_checked(request, 'parent_id')
    return create_resource(resource_name, resource_type, parent_id, request.db)


@view_config(route_name=ResourceAPI.name, request_method='DELETE')
def delete_resource_view(request):
    return delete_resource(request)


@view_config(route_name='resource', request_method='PUT')
def update_resource(request):
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
                  fallback=lambda: request.db.rollback(),
                  msgOnFail="Failed to update resource with new name",
                  content={u'resource_id': resource.resource_id, u'resource_name': resource.resource_name,
                           u'old_resource_name': res_old_name, u'new_resource_name': res_new_name})
    return valid_http(httpSuccess=HTTPOk, detail="Update resource successful",
                      content={u'resource_id': resource.resource_id, u'resource_name': resource.resource_name,
                               u'old_resource_name': res_old_name, u'new_resource_name': res_new_name})


@view_config(route_name='resource_permissions', request_method='GET')
def get_resource_permissions_view(request):
    resource = get_resource_matchdict_checked(request, 'resource_id')
    res_perm = evaluate_call(lambda: get_resource_permissions(resource, db_session=request.db),
                             fallback=lambda: request.db.rollback(), httpError=HTTPNotAcceptable,
                             msgOnFail="Invalid resource type to extract permissions",
                             content=format_resource(resource, basic_info=True))
    return valid_http(httpSuccess=HTTPOk, detail="Get resource permissions successful",
                      content={u'permission_names': res_perm})
