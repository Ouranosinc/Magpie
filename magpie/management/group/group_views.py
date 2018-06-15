from group_utils import *
from ziggurat_definitions import *


@view_config(route_name='groups', request_method='GET')
def get_groups(request):
    group_names = get_all_groups(request.db)
    return valid_http(httpSuccess=HTTPOk, detail="Get groups successful", content={u'group_names': group_names})


@view_config(route_name='groups', request_method='POST')
def create_group(request):
    group_name = get_value_multiformat_post_checked(request, 'group_name')
    group = GroupService.by_group_name(group_name, db_session=request.db)
    group_content_error = {u'group_name': str(group_name)}
    verify_param(group, isNone=True, httpError=HTTPConflict, withParam=False,
                 msgOnFail="Group already exists with this name", content=group_content_error)
    new_group = evaluate_call(lambda: models.Group(group_name=group_name), fallback=lambda: request.db.rollback(),
                              httpError=HTTPForbidden, msgOnFail="Create new group by name refused by db",
                              content=group_content_error)
    evaluate_call(lambda: request.db.add(new_group), fallback=lambda: request.db.rollback(),
                  httpError=HTTPConflict, msgOnFail="Add new group by name refused by db",
                  content=group_content_error)
    return valid_http(httpSuccess=HTTPCreated, detail="Create group successful",
                      content={u'group': format_group(new_group)})


@view_config(route_name='group', request_method='PUT')
def edit_group(request):
    group = get_group_matchdict_checked(request, group_name_key='group_name')
    new_group_name = get_multiformat_post(request, 'group_name')
    verify_param(new_group_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `group_name` value specified.")
    verify_param(len(new_group_name), isIn=True, httpError=HTTPNotAcceptable,
                 paramCompare=range(1, 1 + USER_NAME_MAX_LENGTH),
                 msgOnFail="Invalid `group_name` length specified " +
                           "(>{length} characters).".format(length=USER_NAME_MAX_LENGTH))
    verify_param(new_group_name, notEqual=True, httpError=HTTPNotAcceptable,
                 paramCompare=group.group_name, msgOnFail="Invalid `group_name` must be different than current name.")
    verify_param(models.Group.by_group_name(new_group_name, db_session=request.db), isNone=True, httpError=HTTPConflict,
                 msgOnFail="Group name already exists.")
    group.group_name = new_group_name
    return valid_http(httpSuccess=HTTPOk, detail="Update group successful.")


@view_config(route_name='group', request_method='DELETE')
def delete_group(request):
    group = get_group_matchdict_checked(request)
    evaluate_call(lambda: request.db.delete(group), fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete group forbidden by db")
    return valid_http(httpSuccess=HTTPOk, detail="Delete group successful")


@view_config(route_name='group_users', request_method='GET')
def get_group_users(request):
    group = get_group_matchdict_checked(request)
    user_names = evaluate_call(lambda: [user.user_name for user in group.users],
                               httpError=HTTPForbidden, msgOnFail="Failed to obtain group user names from db")
    return valid_http(httpSuccess=HTTPOk, detail="Get group users successful", content={u'user_names': user_names})


@view_config(route_name='group_services', request_method='GET')
def get_group_services_view(request):
    group = get_group_matchdict_checked(request)
    res_perm_dict = get_group_resources_permissions_dict(group, resource_types=[u'service'], db_session=request.db)
    grp_svc_json = evaluate_call(lambda: get_group_services(res_perm_dict, request.db),
                                 httpError=HTTPInternalServerError, msgOnFail="Failed to populate group services",
                                 content={u'group': format_group(group)})
    return valid_http(httpSuccess=HTTPOk, detail="Get group services successful", content={u'services': grp_svc_json})


@view_config(route_name='group_service_permissions', request_method='GET')
def get_group_service_permissions_view(request):
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    svc_perms_found = evaluate_call(lambda: get_group_service_permissions(group, service, request.db),
                                    httpError=HTTPInternalServerError,
                                    msgOnFail="Failed to extract permissions names from group-service",
                                    content={u'group': format_group(group), u'service': format_service(service)})
    return valid_http(httpSuccess=HTTPOk, detail="Get group service permissions successful",
                      content={u'permission_names': svc_perms_found})


@view_config(route_name='group_service_permissions', request_method='POST')
def create_group_service_permission(request):
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, service)
    return create_group_resource_permission(perm_name, service, group, db_session=request.db)


@view_config(route_name='group_service_permission', request_method='DELETE')
def delete_group_service_permission(request):
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, service)
    return delete_group_resource_permission(perm_name, service, group, db_session=request.db)


@view_config(route_name='group_resources', request_method='GET')
def get_group_resources_view(request):
    group = get_group_matchdict_checked(request)
    grp_res_json = evaluate_call(lambda: get_group_resources(group, request.db), fallback=lambda: request.db.rollback(),
                                 httpError=HTTPInternalServerError, content={u'group': repr(group)},
                                 msgOnFail="Failed to build group resources json tree")
    return valid_http(httpSuccess=HTTPOk, detail="Get group resources successful", content={u'resources': grp_res_json})


@view_config(route_name='group_resource_permissions', request_method='GET')
def get_group_resource_permissions_view(request):
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_names = get_group_resource_permissions(group, resource, db_session=request.db)
    return valid_http(httpSuccess=HTTPOk, detail="Get group resource permissions successful",
                      content={u'permission_names': perm_names})


@view_config(route_name='group_resource_permissions', request_method='POST')
def create_group_resource_permission_view(request):
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, resource)
    return create_group_resource_permission(perm_name, resource, group, db_session=request.db)


@view_config(route_name='group_resource_permission', request_method='DELETE')
def delete_group_resource_permission_view(request):
    group = get_group_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, resource)
    return delete_group_resource_permission(perm_name, resource, group, db_session=request.db)


@view_config(route_name='group_service_resources', request_method='GET')
def get_group_service_resources_view(request):
    group = get_group_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    svc_perms = get_group_service_permissions(group=group, service=service, db_session=request.db)
    res_perms = get_group_service_resources_permissions_dict(group=group, service=service, db_session=request.db)
    svc_res_json = format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=svc_perms,
        resources_perms_dict=res_perms,
        display_all=False
    )
    return valid_http(httpSuccess=HTTPOk, detail="Get group service resources successful",
                      content={u'service': svc_res_json})
