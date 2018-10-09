from magpie.api.management.group.group_utils import *
from magpie.api.api_rest_schemas import *
from magpie.definitions.ziggurat_definitions import *
from magpie.definitions.pyramid_definitions import view_config


@GroupsAPI.get(tags=[GroupsTag], response_schemas=Groups_GET_responses)
@view_config(route_name=GroupsAPI.name, request_method='GET')
def get_groups(request):
    """Get list of group names."""
    group_names = get_all_groups(request.db)
    return valid_http(httpSuccess=HTTPOk, detail=Groups_GET_OkResponseSchema.description,
                      content={u'group_names': group_names})


@GroupsAPI.post(schema=Groups_POST_RequestSchema(), tags=[GroupsTag], response_schemas=Groups_POST_responses)
@view_config(route_name=GroupsAPI.name, request_method='POST')
def create_group(request):
    """Create a group."""
    group_name = get_value_multiformat_post_checked(request, 'group_name')
    group = GroupService.by_group_name(group_name, db_session=request.db)
    group_content_error = {u'group_name': str(group_name)}
    verify_param(group, isNone=True, httpError=HTTPConflict, withParam=False,
                 msgOnFail=Groups_POST_ConflictResponseSchema.description, content=group_content_error)
    new_group = evaluate_call(lambda: models.Group(group_name=group_name), fallback=lambda: request.db.rollback(),
                              httpError=HTTPForbidden, msgOnFail=Groups_POST_ForbiddenCreateResponseSchema.description,
                              content=group_content_error)
    evaluate_call(lambda: request.db.add(new_group), fallback=lambda: request.db.rollback(),
                  httpError=HTTPForbidden, msgOnFail=Groups_POST_ForbiddenAddResponseSchema.description,
                  content=group_content_error)
    return valid_http(httpSuccess=HTTPCreated, detail=Groups_POST_CreatedResponseSchema.description,
                      content={u'group': format_group(new_group, basic_info=True)})


@GroupAPI.get(tags=[GroupsTag], response_schemas=Group_GET_responses)
@view_config(route_name=GroupAPI.name, request_method='GET')
def get_group(request):
    """Get group information."""
    group = get_group_matchdict_checked(request, group_name_key='group_name')
    return valid_http(httpSuccess=HTTPOk, detail=Group_GET_OkResponseSchema.description,
                      content={u'group': format_group(group)})


@GroupAPI.put(schema=Group_PUT_RequestSchema(), tags=[GroupsTag], response_schemas=Group_PUT_responses)
@view_config(route_name=GroupAPI.name, request_method='PUT')
def edit_group(request):
    """Update a group by name."""
    group = get_group_matchdict_checked(request, group_name_key='group_name')
    new_group_name = get_multiformat_post(request, 'group_name')
    verify_param(new_group_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail=Group_PUT_Name_NotAcceptableResponseSchema.description)
    verify_param(len(new_group_name), isIn=True, httpError=HTTPNotAcceptable,
                 paramCompare=range(1, 1 + MAGPIE_USER_NAME_MAX_LENGTH),
                 msgOnFail=Group_PUT_Size_NotAcceptableResponseSchema.description)
    verify_param(new_group_name, notEqual=True, httpError=HTTPNotAcceptable,
                 paramCompare=group.group_name, msgOnFail=Group_PUT_Same_NotAcceptableResponseSchema.description)
    verify_param(models.Group.by_group_name(new_group_name, db_session=request.db), isNone=True, httpError=HTTPConflict,
                 msgOnFail=Group_PUT_ConflictResponseSchema.description)
    group.group_name = new_group_name
    return valid_http(httpSuccess=HTTPOk, detail=Group_PUT_OkResponseSchema.description)


@GroupAPI.delete(schema=Group_DELETE_RequestSchema(), tags=[GroupsTag], response_schemas=Group_DELETE_responses)
@view_config(route_name=GroupAPI.name, request_method='DELETE')
def delete_group(request):
    """Delete a group by name."""
    group = get_group_matchdict_checked(request)
    evaluate_call(lambda: request.db.delete(group), fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail=Group_DELETE_ForbiddenResponseSchema.description)
    return valid_http(httpSuccess=HTTPOk, detail=Group_DELETE_OkResponseSchema.description)


@GroupUsersAPI.get(tags=[GroupsTag], response_schemas=GroupUsers_GET_responses)
@view_config(route_name=GroupUsersAPI.name, request_method='GET')
def get_group_users(request):
    """List all user from a group."""
    group = get_group_matchdict_checked(request)
    user_names = evaluate_call(lambda: [user.user_name for user in group.users],
                               httpError=HTTPForbidden, msgOnFail=GroupUsers_GET_ForbiddenResponseSchema.description)
    return valid_http(httpSuccess=HTTPOk, detail=GroupUsers_GET_OkResponseSchema.description,
                      content={u'user_names': sorted(user_names)})


@GroupServicesAPI.get(tags=[GroupsTag], response_schemas=GroupServices_GET_responses)
@view_config(route_name=GroupServicesAPI.name, request_method='GET')
def get_group_services_view(request):
    """List all services a group has permission on."""
    group = get_group_matchdict_checked(request)
    res_perm_dict = get_group_resources_permissions_dict(group, resource_types=[u'service'], db_session=request.db)
    grp_svc_json = evaluate_call(lambda: get_group_services(res_perm_dict, request.db),
                                 httpError=HTTPInternalServerError,
                                 msgOnFail=GroupServices_InternalServerErrorResponseSchema.description,
                                 content={u'group': format_group(group)})
    return valid_http(httpSuccess=HTTPOk, detail=GroupServices_GET_OkResponseSchema.description,
                      content={u'services': grp_svc_json})


@GroupServicePermissionsAPI.get(tags=[GroupsTag], response_schemas=GroupServicePermissions_GET_responses)
@view_config(route_name=GroupServicePermissionsAPI.name, request_method='GET')
def get_group_service_permissions_view(request):
    """List all permissions a group has on a specific service."""
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    svc_perms_found = evaluate_call(lambda: get_group_service_permissions(group, service, request.db),
                                    httpError=HTTPInternalServerError,
                                    msgOnFail=GroupServicePermissions_GET_InternalServerErrorResponseSchema.description,
                                    content={u'group': format_group(group), u'service': format_service(service)})
    return valid_http(httpSuccess=HTTPOk, detail=GroupServicePermissions_GET_OkResponseSchema.description,
                      content={u'permission_names': svc_perms_found})


@GroupServicePermissionsAPI.post(schema=GroupServicePermissions_POST_RequestSchema(), tags=[GroupsTag],
                                 response_schemas=GroupServicePermissions_POST_responses)
@view_config(route_name=GroupServicePermissionsAPI.name, request_method='POST')
def create_group_service_permission(request):
    """Create a permission on a specific resource for a group."""
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, service)
    return create_group_resource_permission(perm_name, service, group, db_session=request.db)


@GroupServicePermissionAPI.delete(schema=GroupServicePermission_DELETE_RequestSchema(), tags=[GroupsTag],
                                  response_schemas=GroupServicePermission_DELETE_responses)
@view_config(route_name=GroupServicePermissionAPI.name, request_method='DELETE')
def delete_group_service_permission(request):
    """Delete a permission from a specific resource for a group."""
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, service)
    return delete_group_resource_permission(perm_name, service, group, db_session=request.db)


@GroupResourcesAPI.get(tags=[GroupsTag], response_schemas=GroupResources_GET_responses)
@view_config(route_name=GroupResourcesAPI.name, request_method='GET')
def get_group_resources_view(request):
    """List all resources a group has permission on."""
    group = get_group_matchdict_checked(request)
    grp_res_json = evaluate_call(lambda: get_group_resources(group, request.db), fallback=lambda: request.db.rollback(),
                                 httpError=HTTPInternalServerError, content={u'group': repr(group)},
                                 msgOnFail=GroupResources_GET_InternalServerErrorResponseSchema.description)
    return valid_http(httpSuccess=HTTPOk, detail=GroupResources_GET_OkResponseSchema.description,
                      content={u'resources': grp_res_json})


@GroupResourcePermissionsAPI.get(tags=[GroupsTag], response_schemas=GroupResourcePermissions_GET_responses)
@view_config(route_name=GroupResourcePermissionsAPI.name, request_method='GET')
def get_group_resource_permissions_view(request):
    """List all permissions a group has on a specific resource."""
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_names = get_group_resource_permissions(group, resource, db_session=request.db)
    return valid_http(httpSuccess=HTTPOk, detail=GroupResourcePermissions_GET_OkResponseSchema.description,
                      content={u'permission_names': perm_names})


@GroupResourcePermissionsAPI.post(schema=GroupResourcePermissions_POST_RequestSchema(), tags=[GroupsTag],
                                  response_schemas=GroupResourcePermissions_POST_responses)
@view_config(route_name=GroupResourcePermissionsAPI.name, request_method='POST')
def create_group_resource_permission_view(request):
    """Create a permission on a specific resource for a group."""
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, resource)
    return create_group_resource_permission(perm_name, resource, group, db_session=request.db)


@GroupResourcePermissionAPI.post(schema=GroupResourcePermission_DELETE_RequestSchema(), tags=[GroupsTag],
                                 response_schemas=GroupResourcePermission_DELETE_responses)
@view_config(route_name=GroupResourcePermissionAPI.name, request_method='DELETE')
def delete_group_resource_permission_view(request):
    """Delete a permission from a specific resource for a group."""
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, resource)
    return delete_group_resource_permission(perm_name, resource, group, db_session=request.db)


@GroupServiceResourcesAPI.get(tags=[GroupsTag], response_schemas=GroupServiceResources_GET_responses)
@view_config(route_name=GroupServiceResourcesAPI.name, request_method='GET')
def get_group_service_resources_view(request):
    """List all resources under a service a group has permission on."""
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    svc_perms = get_group_service_permissions(group=group, service=service, db_session=request.db)
    res_perms = get_group_service_resources_permissions_dict(group=group, service=service, db_session=request.db)
    svc_res_json = format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=svc_perms,
        resources_perms_dict=res_perms,
        display_all=False,
        show_private_url=False,
    )
    return valid_http(httpSuccess=HTTPOk, detail=GroupServiceResources_GET_OkResponseSchema.description,
                      content={u'service': svc_res_json})
