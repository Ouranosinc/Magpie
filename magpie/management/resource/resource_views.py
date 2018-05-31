from api_requests import *
from resource_utils import *
from common import str2bool
from register import sync_services_phoenix


@view_config(route_name='resource', request_method='GET')
def get_resource_view(request):
    res = get_resource_matchdict_checked(request)
    res_json = evaluate_call(lambda: format_resource_with_children(res, db_session=request.db),
                             fallback=lambda: request.db.rollback(), httpError=HTTPInternalServerError,
                             msgOnFail="Failed building resource children json formatted tree",
                             content=format_resource(res, basic_info=True))
    return valid_http(httpSuccess=HTTPOk, detail="Get resource successful", content={res.resource_id: res_json})


@view_config(route_name='resources', request_method='POST')
def create_resource_view(request):
    resource_name = get_value_multiformat_post_checked(request, 'resource_name')
    resource_type = get_value_multiformat_post_checked(request, 'resource_type')
    parent_id = get_value_multiformat_post_checked(request, 'parent_id')
    return create_resource(resource_name, resource_type, parent_id, request.db)


@view_config(route_name='service_resource', request_method='DELETE')
@view_config(route_name='resource', request_method='DELETE')
def delete_resources(request):
    resource = get_resource_matchdict_checked(request)
    service_push = str2bool(get_multiformat_post(request, 'service_push'))
    res_content = format_resource(resource, basic_info=True)
    evaluate_call(lambda: resource_tree_service.delete_branch(resource_id=resource.resource_id, db_session=request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete resource branch from tree service failed", content=res_content)

    def remove_service_magpie_and_phoenix(res, svc_push, db):
        if res.resource_type != 'service':
            svc_push = False
        db.delete(res)
        if svc_push:
            sync_services_phoenix(db.query(models.Service))

    evaluate_call(lambda: remove_service_magpie_and_phoenix(resource, service_push, request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete resource from db failed", content=res_content)
    return valid_http(httpSuccess=HTTPOk, detail="Delete resource successful")


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
def get_resource_permissions(request):
    res = get_resource_matchdict_checked(request, 'resource_id')
    res_perm = evaluate_call(lambda: resource_type_dict[res.resource_type].permission_names,
                             fallback=lambda: request.db.rollback(), httpError=HTTPNotAcceptable,
                             msgOnFail="Invalid resource type to extract permissions",
                             content=format_resource(res, basic_info=True))
    return valid_http(httpSuccess=HTTPOk, detail="Get resource permissions successful",
                      content={u'permission_names': res_perm})
