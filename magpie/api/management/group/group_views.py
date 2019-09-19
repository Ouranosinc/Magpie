from magpie.api import requests as ar, exception as ax, schemas as s
from magpie.api.management.group import group_utils as gu, group_formats as gf
from magpie.constants import get_constant
from magpie.definitions.ziggurat_definitions import GroupService
from magpie.definitions.pyramid_definitions import (
    view_config,
    HTTPOk,
    HTTPBadRequest,
    HTTPForbidden,
    HTTPConflict,
    HTTPInternalServerError,
)


@s.GroupsAPI.get(tags=[s.GroupsTag], response_schemas=s.Groups_GET_responses)
@view_config(route_name=s.GroupsAPI.name, request_method="GET")
def get_groups_view(request):
    """
    Get list of group names.
    """
    group_names = gu.get_all_group_names(request.db)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.Groups_GET_OkResponseSchema.description,
                         content={u"group_names": group_names})


@s.GroupsAPI.post(schema=s.Groups_POST_RequestSchema(), tags=[s.GroupsTag], response_schemas=s.Groups_POST_responses)
@view_config(route_name=s.GroupsAPI.name, request_method="POST")
def create_group_view(request):
    """
    Create a group.
    """
    group_name = ar.get_value_multiformat_post_checked(request, "group_name")
    return gu.create_group(group_name, request.db)


@s.GroupAPI.get(tags=[s.GroupsTag], response_schemas=s.Group_GET_responses)
@view_config(route_name=s.GroupAPI.name, request_method="GET")
def get_group_view(request):
    """
    Get group information.
    """
    group = ar.get_group_matchdict_checked(request, group_name_key="group_name")
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.Group_GET_OkResponseSchema.description,
                         content={u"group": gf.format_group(group, db_session=request.db)})


@s.GroupAPI.put(schema=s.Group_PUT_RequestSchema(), tags=[s.GroupsTag], response_schemas=s.Group_PUT_responses)
@view_config(route_name=s.GroupAPI.name, request_method="PUT")
def edit_group_view(request):
    """
    Update a group by name.
    """
    group = ar.get_group_matchdict_checked(request, group_name_key="group_name")
    new_group_name = ar.get_multiformat_post(request, "group_name")
    ax.verify_param(new_group_name, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                    msgOnFail=s.Group_PUT_Name_BadRequestResponseSchema.description)
    ax.verify_param(len(new_group_name), isIn=True, httpError=HTTPBadRequest,
                    paramCompare=range(1, 1 + get_constant("MAGPIE_USER_NAME_MAX_LENGTH")),
                    msgOnFail=s.Group_PUT_Size_BadRequestResponseSchema.description)
    ax.verify_param(new_group_name, notEqual=True, httpError=HTTPBadRequest,
                    paramCompare=group.group_name, msgOnFail=s.Group_PUT_Same_BadRequestResponseSchema.description)
    ax.verify_param(GroupService.by_group_name(new_group_name, db_session=request.db),
                    isNone=True, httpError=HTTPConflict,
                    msgOnFail=s.Group_PUT_ConflictResponseSchema.description)
    group.group_name = new_group_name
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.Group_PUT_OkResponseSchema.description)


@s.GroupAPI.delete(schema=s.Group_DELETE_RequestSchema(), tags=[s.GroupsTag], response_schemas=s.Group_DELETE_responses)
@view_config(route_name=s.GroupAPI.name, request_method="DELETE")
def delete_group_view(request):
    """
    Delete a group by name.
    """
    group = ar.get_group_matchdict_checked(request)
    ax.evaluate_call(lambda: request.db.delete(group),
                     fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                     msgOnFail=s.Group_DELETE_ForbiddenResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.Group_DELETE_OkResponseSchema.description)


@s.GroupUsersAPI.get(tags=[s.GroupsTag], response_schemas=s.GroupUsers_GET_responses)
@view_config(route_name=s.GroupUsersAPI.name, request_method="GET")
def get_group_users_view(request):
    """
    List all user from a group.
    """
    group = ar.get_group_matchdict_checked(request)
    user_names = ax.evaluate_call(lambda: [user.user_name for user in group.users],
                                  httpError=HTTPForbidden,
                                  msgOnFail=s.GroupUsers_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.GroupUsers_GET_OkResponseSchema.description,
                         content={u"user_names": sorted(user_names)})


@s.GroupServicesAPI.get(tags=[s.GroupsTag], response_schemas=s.GroupServices_GET_responses)
@view_config(route_name=s.GroupServicesAPI.name, request_method="GET")
def get_group_services_view(request):
    """
    List all services a group has permission on.
    """
    group = ar.get_group_matchdict_checked(request)
    return gu.get_group_services_response(group, request.db)


@s.GroupServicePermissionsAPI.get(tags=[s.GroupsTag], response_schemas=s.GroupServicePermissions_GET_responses)
@view_config(route_name=s.GroupServicePermissionsAPI.name, request_method="GET")
def get_group_service_permissions_view(request):
    """
    List all permissions a group has on a specific service.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    return gu.get_group_service_permissions_response(group, service, request.db)


@s.GroupServicePermissionsAPI.post(schema=s.GroupServicePermissions_POST_RequestSchema(), tags=[s.GroupsTag],
                                   response_schemas=s.GroupServicePermissions_POST_responses)
@view_config(route_name=s.GroupServicePermissionsAPI.name, request_method="POST")
def create_group_service_permission_view(request):
    """
    Create a permission on a specific resource for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_multiformat_post_checked(request, service)
    return gu.create_group_resource_permission_response(group, service, permission, db_session=request.db)


@s.GroupServicePermissionAPI.delete(schema=s.GroupServicePermission_DELETE_RequestSchema(), tags=[s.GroupsTag],
                                    response_schemas=s.GroupServicePermission_DELETE_responses)
@view_config(route_name=s.GroupServicePermissionAPI.name, request_method="DELETE")
def delete_group_service_permission_view(request):
    """
    Delete a permission from a specific service for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, service)
    return gu.delete_group_resource_permission_response(group, service, permission, db_session=request.db)


@s.GroupResourcesAPI.get(tags=[s.GroupsTag], response_schemas=s.GroupResources_GET_responses)
@view_config(route_name=s.GroupResourcesAPI.name, request_method="GET")
def get_group_resources_view(request):
    """
    List all resources a group has permission on.
    """
    group = ar.get_group_matchdict_checked(request)
    grp_res_json = ax.evaluate_call(lambda: gu.get_group_resources(group, request.db),
                                    fallback=lambda: request.db.rollback(),
                                    httpError=HTTPInternalServerError, content={u"group": repr(group)},
                                    msgOnFail=s.GroupResources_GET_InternalServerErrorResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.GroupResources_GET_OkResponseSchema.description,
                         content={u"resources": grp_res_json})


@s.GroupResourcePermissionsAPI.get(tags=[s.GroupsTag], response_schemas=s.GroupResourcePermissions_GET_responses)
@view_config(route_name=s.GroupResourcePermissionsAPI.name, request_method="GET")
def get_group_resource_permissions_view(request):
    """
    List all permissions a group has on a specific resource.
    """
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    return gu.get_group_resource_permissions_response(group, resource, db_session=request.db)


@s.GroupResourcePermissionsAPI.post(schema=s.GroupResourcePermissions_POST_RequestSchema(), tags=[s.GroupsTag],
                                    response_schemas=s.GroupResourcePermissions_POST_responses)
@view_config(route_name=s.GroupResourcePermissionsAPI.name, request_method="POST")
def create_group_resource_permission_view(request):
    """
    Create a permission on a specific resource for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_multiformat_post_checked(request, resource)
    return gu.create_group_resource_permission_response(group, resource, permission, db_session=request.db)


@s.GroupResourcePermissionAPI.delete(schema=s.GroupResourcePermission_DELETE_RequestSchema(), tags=[s.GroupsTag],
                                     response_schemas=s.GroupResourcePermission_DELETE_responses)
@view_config(route_name=s.GroupResourcePermissionAPI.name, request_method="DELETE")
def delete_group_resource_permission_view(request):
    """
    Delete a permission from a specific resource for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, resource)
    return gu.delete_group_resource_permission_response(group, resource, permission, db_session=request.db)


@s.GroupServiceResourcesAPI.get(tags=[s.GroupsTag], response_schemas=s.GroupServiceResources_GET_responses)
@view_config(route_name=s.GroupServiceResourcesAPI.name, request_method="GET")
def get_group_service_resources_view(request):
    """
    List all resources under a service a group has permission on.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    return gu.get_group_service_resources_response(group, service, request.db)
