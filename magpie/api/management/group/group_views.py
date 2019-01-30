from magpie.api import api_requests as ar, api_except as ax
from magpie.api.management.group import group_utils as gu, group_formats as gf
from magpie.api.management.service.service_formats import format_service, format_service_resources
from magpie.api.api_rest_schemas import *
from magpie.constants import get_constant
from magpie.definitions.ziggurat_definitions import *
from magpie.definitions.pyramid_definitions import view_config
from magpie import models


@GroupsAPI.get(tags=[GroupsTag], response_schemas=Groups_GET_responses)
@view_config(route_name=GroupsAPI.name, request_method='GET')
def get_groups_view(request):
    """Get list of group names."""
    group_names = gu.get_all_groups(request.db)
    return ax.valid_http(httpSuccess=HTTPOk, detail=Groups_GET_OkResponseSchema.description,
                         content={u'group_names': group_names})


@GroupsAPI.post(schema=Groups_POST_RequestSchema(), tags=[GroupsTag], response_schemas=Groups_POST_responses)
@view_config(route_name=GroupsAPI.name, request_method='POST')
def create_group_view(request):
    """Create a group."""
    group_name = ar.get_value_multiformat_post_checked(request, 'group_name')
    return gu.create_group(group_name, request.db)


@GroupAPI.get(tags=[GroupsTag], response_schemas=Group_GET_responses)
@view_config(route_name=GroupAPI.name, request_method='GET')
def get_group_view(request):
    """Get group information."""
    group = ar.get_group_matchdict_checked(request, group_name_key='group_name')
    return ax.valid_http(httpSuccess=HTTPOk, detail=Group_GET_OkResponseSchema.description,
                         content={u'group': gf.format_group(group)})


@GroupAPI.put(schema=Group_PUT_RequestSchema(), tags=[GroupsTag], response_schemas=Group_PUT_responses)
@view_config(route_name=GroupAPI.name, request_method='PUT')
def edit_group_view(request):
    """Update a group by name."""
    group = ar.get_group_matchdict_checked(request, group_name_key='group_name')
    new_group_name = ar.get_multiformat_post(request, 'group_name')
    ax.verify_param(new_group_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                    msgOnFail=Group_PUT_Name_NotAcceptableResponseSchema.description)
    ax.verify_param(len(new_group_name), isIn=True, httpError=HTTPNotAcceptable,
                    paramCompare=range(1, 1 + get_constant('MAGPIE_USER_NAME_MAX_LENGTH')),
                    msgOnFail=Group_PUT_Size_NotAcceptableResponseSchema.description)
    ax.verify_param(new_group_name, notEqual=True, httpError=HTTPNotAcceptable,
                    paramCompare=group.group_name, msgOnFail=Group_PUT_Same_NotAcceptableResponseSchema.description)
    ax.verify_param(GroupService.by_group_name(new_group_name, db_session=request.db),
                    isNone=True, httpError=HTTPConflict,
                    msgOnFail=Group_PUT_ConflictResponseSchema.description)
    group.group_name = new_group_name
    return ax.valid_http(httpSuccess=HTTPOk, detail=Group_PUT_OkResponseSchema.description)


@GroupAPI.delete(schema=Group_DELETE_RequestSchema(), tags=[GroupsTag], response_schemas=Group_DELETE_responses)
@view_config(route_name=GroupAPI.name, request_method='DELETE')
def delete_group_view(request):
    """Delete a group by name."""
    group = ar.get_group_matchdict_checked(request)
    ax.evaluate_call(lambda: request.db.delete(group),
                     fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                     msgOnFail=Group_DELETE_ForbiddenResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=Group_DELETE_OkResponseSchema.description)


@GroupUsersAPI.get(tags=[GroupsTag], response_schemas=GroupUsers_GET_responses)
@view_config(route_name=GroupUsersAPI.name, request_method='GET')
def get_group_users_view(request):
    """List all user from a group."""
    group = ar.get_group_matchdict_checked(request)
    user_names = ax.evaluate_call(lambda: [user.user_name for user in group.users],
                                  httpError=HTTPForbidden,
                                  msgOnFail=GroupUsers_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=GroupUsers_GET_OkResponseSchema.description,
                         content={u'user_names': sorted(user_names)})


@GroupServicesAPI.get(tags=[GroupsTag], response_schemas=GroupServices_GET_responses)
@view_config(route_name=GroupServicesAPI.name, request_method='GET')
def get_group_services_view(request):
    """List all services a group has permission on."""
    group = ar.get_group_matchdict_checked(request)
    res_perm_dict = gu.get_group_resources_permissions_dict(group,
                                                            resource_types=[models.Service.resource_type_name],
                                                            db_session=request.db)
    grp_svc_json = ax.evaluate_call(lambda: gu.get_group_services(res_perm_dict, request.db),
                                    httpError=HTTPInternalServerError,
                                    msgOnFail=GroupServices_InternalServerErrorResponseSchema.description,
                                    content={u'group': gf.format_group(group)})
    return ax.valid_http(httpSuccess=HTTPOk, detail=GroupServices_GET_OkResponseSchema.description,
                         content={u'services': grp_svc_json})


@GroupServicePermissionsAPI.get(tags=[GroupsTag], response_schemas=GroupServicePermissions_GET_responses)
@view_config(route_name=GroupServicePermissionsAPI.name, request_method='GET')
def get_group_service_permissions_view(request):
    """List all permissions a group has on a specific service."""
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    svc_perms_found = ax.evaluate_call(
        lambda: gu.get_group_service_permissions(group, service, request.db),
        httpError=HTTPInternalServerError,
        msgOnFail=GroupServicePermissions_GET_InternalServerErrorResponseSchema.description,
        content={u'group': gf.format_group(group), u'service': format_service(service)})
    return ax.valid_http(httpSuccess=HTTPOk, detail=GroupServicePermissions_GET_OkResponseSchema.description,
                         content={u'permission_names': svc_perms_found})


@GroupServicePermissionsAPI.post(schema=GroupServicePermissions_POST_RequestSchema(), tags=[GroupsTag],
                                 response_schemas=GroupServicePermissions_POST_responses)
@view_config(route_name=GroupServicePermissionsAPI.name, request_method='POST')
def create_group_service_permission_view(request):
    """Create a permission on a specific resource for a group."""
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    perm_name = ar.get_permission_multiformat_post_checked(request, service)
    return gu.create_group_resource_permission(perm_name, service, group, db_session=request.db)


@GroupServicePermissionAPI.delete(schema=GroupServicePermission_DELETE_RequestSchema(), tags=[GroupsTag],
                                  response_schemas=GroupServicePermission_DELETE_responses)
@view_config(route_name=GroupServicePermissionAPI.name, request_method='DELETE')
def delete_group_service_permission_view(request):
    """Delete a permission from a specific service for a group."""
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    perm_name = ar.get_permission_matchdict_checked(request, service)
    return gu.delete_group_resource_permission(perm_name, service, group, db_session=request.db)


@GroupResourcesAPI.get(tags=[GroupsTag], response_schemas=GroupResources_GET_responses)
@view_config(route_name=GroupResourcesAPI.name, request_method='GET')
def get_group_resources_view(request):
    """List all resources a group has permission on."""
    group = ar.get_group_matchdict_checked(request)
    grp_res_json = ax.evaluate_call(lambda: gu.get_group_resources(group, request.db),
                                    fallback=lambda: request.db.rollback(),
                                    httpError=HTTPInternalServerError, content={u'group': repr(group)},
                                    msgOnFail=GroupResources_GET_InternalServerErrorResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=GroupResources_GET_OkResponseSchema.description,
                         content={u'resources': grp_res_json})


@GroupResourcePermissionsAPI.get(tags=[GroupsTag], response_schemas=GroupResourcePermissions_GET_responses)
@view_config(route_name=GroupResourcePermissionsAPI.name, request_method='GET')
def get_group_resource_permissions_view(request):
    """List all permissions a group has on a specific resource."""
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    perm_names = gu.get_group_resource_permissions(group, resource, db_session=request.db)
    return ax.valid_http(httpSuccess=HTTPOk, detail=GroupResourcePermissions_GET_OkResponseSchema.description,
                         content={u'permission_names': perm_names})


@GroupResourcePermissionsAPI.post(schema=GroupResourcePermissions_POST_RequestSchema(), tags=[GroupsTag],
                                  response_schemas=GroupResourcePermissions_POST_responses)
@view_config(route_name=GroupResourcePermissionsAPI.name, request_method='POST')
def create_group_resource_permission_view(request):
    """Create a permission on a specific resource for a group."""
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    perm_name = ar.get_permission_multiformat_post_checked(request, resource)
    return gu.create_group_resource_permission(perm_name, resource, group, db_session=request.db)


@GroupResourcePermissionAPI.delete(schema=GroupResourcePermission_DELETE_RequestSchema(), tags=[GroupsTag],
                                   response_schemas=GroupResourcePermission_DELETE_responses)
@view_config(route_name=GroupResourcePermissionAPI.name, request_method='DELETE')
def delete_group_resource_permission_view(request):
    """Delete a permission from a specific resource for a group."""
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    perm_name = ar.get_permission_matchdict_checked(request, resource)
    return gu.delete_group_resource_permission(perm_name, resource, group, db_session=request.db)


@GroupServiceResourcesAPI.get(tags=[GroupsTag], response_schemas=GroupServiceResources_GET_responses)
@view_config(route_name=GroupServiceResourcesAPI.name, request_method='GET')
def get_group_service_resources_view(request):
    """List all resources under a service a group has permission on."""
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    svc_perms = gu.get_group_service_permissions(group=group, service=service, db_session=request.db)
    res_perms = gu.get_group_service_resources_permissions_dict(group=group, service=service, db_session=request.db)
    svc_res_json = format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=svc_perms,
        resources_perms_dict=res_perms,
        display_all=False,
        show_private_url=False,
    )
    return ax.valid_http(httpSuccess=HTTPOk, detail=GroupServiceResources_GET_OkResponseSchema.description,
                         content={u'service': svc_res_json})
