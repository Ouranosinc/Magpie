from definitions.pyramid_definitions import *
from definitions.ziggurat_definitions import *
from api.api_requests import *
from api.management.user.user_utils import *
from api.management.service.service_formats import format_service, format_service_resources


@view_config(route_name=UsersAPI.name, request_method='POST')
def create_user_view(request):
    user_name = get_multiformat_post(request, 'user_name')
    email = get_multiformat_post(request, 'email')
    password = get_multiformat_post(request, 'password')
    group_name = get_multiformat_post(request, 'group_name')
    check_user_info(user_name, email, password, group_name)
    return create_user(user_name, password, email, group_name, db_session=request.db)


@view_config(route_name=UserAPI.name, request_method='PUT')
def update_user_view(request):
    user = get_user_matchdict_checked(request, user_name_key='user_name')
    new_user_name = get_multiformat_post(request, 'user_name')
    new_email = get_multiformat_post(request, 'email')
    new_password = get_multiformat_post(request, 'password')
    new_password = user.user_password if new_password is None else new_password
    check_user_info(new_user_name, new_email, new_password, group_name=new_user_name)

    if user.user_name != new_user_name:
        evaluate_call(lambda: models.User.by_user_name(new_user_name, db_session=request.db),
                      fallback=lambda: request.db.rollback(),
                      httpError=HTTPConflict, msgOnFail="New name user already exists")
        user.user_name = new_user_name
    if user.email != new_email:
        user.email = new_email
    if user.user_password != new_password and new_password is not None:
        user.set_password(new_password)
        user.regenerate_security_code()

    return valid_http(httpSuccess=HTTPOk, detail="Update user successful.")


@view_config(route_name=UsersAPI.name, request_method='GET')
def get_users(request):
    user_name_list = evaluate_call(lambda: [user.user_name for user in models.User.all(db_session=request.db)],
                                   fallback=lambda: request.db.rollback(),
                                   httpError=HTTPForbidden, msgOnFail="Get users query refused by db")
    return valid_http(httpSuccess=HTTPOk, detail="Get users successful", content={u'user_names': user_name_list})


@view_config(route_name=UserAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_view(request):
    user = get_user_matchdict_checked(request)
    json_response = {u'user_name': user.user_name,
                     u'email': user.email,
                     u'group_names': [group.group_name for group in user.groups]}
    return valid_http(httpSuccess=HTTPOk, detail="Get user successful", content=json_response)


@view_config(route_name=UserAPI.name, request_method='DELETE')
def delete_user(request):
    user = get_user_matchdict_checked(request)
    db = request.db
    evaluate_call(lambda: db.delete(user), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Delete user by name refused by db")
    return valid_http(httpSuccess=HTTPOk, detail="Delete user successful")


@view_config(route_name=UserGroupsAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_groups(request):
    user = get_user_matchdict_checked(request)
    group_names = get_user_groups_checked(request, user)
    return valid_http(httpSuccess=HTTPOk, detail="Get user groups successful", content={u'group_names': group_names})


@view_config(route_name=UserGroupsAPI.name, request_method='POST')
def assign_user_group(request):
    db = request.db
    user = get_user_matchdict_checked(request)
    group = get_group_matchdict_checked(request)
    new_user_group = models.UserGroup(group_id=group.id, user_id=user.id)

    evaluate_call(lambda: db.add(new_user_group), fallback=lambda: db.rollback(),
                  httpError=HTTPConflict, msgOnFail="User already belongs to this group",
                  content={u'user_name': user.user_name, u'group_name': group.group_name})
    return valid_http(httpSuccess=HTTPCreated, detail="Create user-group assignation successful")


@view_config(route_name=UserGroupAPI.name, request_method='DELETE')
def delete_user_group(request):
    db = request.db
    user = get_user_matchdict_checked(request)
    group = get_group_matchdict_checked(request)

    def del_usr_grp(usr, grp):
        db.query(models.UserGroup) \
            .filter(models.UserGroup.user_id == usr.id) \
            .filter(models.UserGroup.group_id == grp.id) \
            .delete()

    evaluate_call(lambda: del_usr_grp(user, group), fallback=lambda: db.rollback(),
                  httpError=HTTPNotFound, msgOnFail="Invalid user-group combination for delete",
                  content={u'user_name': user.user_name, u'group_name': group.group_name})
    return valid_http(httpSuccess=HTTPOk, detail="Delete user-group successful")


def get_user_resources_runner(request, inherited_group_resources_permissions=True):
    user = get_user_matchdict_checked(request)
    inherit_perms = inherited_group_resources_permissions
    db = request.db

    def build_json_user_resource_tree(usr):
        json_res = {}
        for svc in models.Service.all(db_session=db):
            svc_perms = get_user_service_permissions(user=usr, service=svc, db_session=db,
                                                     inherited_permissions=inherit_perms)
            if svc.type not in json_res:
                json_res[svc.type] = {}
            res_perms_dict = get_user_service_resources_permissions_dict(user=usr, service=svc, db_session=db,
                                                                         inherited_permissions=inherit_perms)
            json_res[svc.type][svc.resource_name] = format_service_resources(
                svc,
                db_session=db,
                service_perms=svc_perms,
                resources_perms_dict=res_perms_dict,
                display_all=False
            )
        return json_res

    usr_res_dict = evaluate_call(lambda: build_json_user_resource_tree(user),
                                 fallback=lambda: db.rollback(), httpError=HTTPNotFound,
                                 msgOnFail="Failed to populate user resources",
                                 content={u'user_name': user.user_name, u'resource_types': [u'service']})
    return valid_http(httpSuccess=HTTPOk, detail="Get user resources successful", content={u'resources': usr_res_dict})


@view_config(route_name=UserResourcesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_resources_view(request):
    return get_user_resources_runner(request, inherited_group_resources_permissions=False)


@view_config(route_name=UserInheritedResourcesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_inherited_resources_view(request):
    return get_user_resources_runner(request, inherited_group_resources_permissions=True)


def get_user_resource_permissions_runner(request, inherited_permissions=True):
    user = get_user_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request, 'resource_id')
    perm_names = get_user_resource_permissions(resource=resource, user=user, db_session=request.db,
                                               inherited_permissions=inherited_permissions)
    return valid_http(httpSuccess=HTTPOk, detail="Get user resource permissions successful",
                      content={u'permission_names': perm_names})


@view_config(route_name=UserResourcePermissionsAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_resource_permissions_view(request):
    return get_user_resource_permissions_runner(request, inherited_permissions=False)


@view_config(route_name=UserResourceInheritedPermissionsAPI.name, request_method='GET',
             permission=NO_PERMISSION_REQUIRED)
def get_user_resource_inherited_permissions_view(request):
    return get_user_resource_permissions_runner(request, inherited_permissions=True)


@view_config(route_name=UserResourcePermissionsAPI.name, request_method='POST')
def create_user_resource_permission_view(request):
    user = get_user_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, resource)
    return create_user_resource_permission(perm_name, resource, user.id, request.db)


@view_config(route_name=UserResourcePermissionAPI.name, request_method='DELETE')
def delete_user_resource_permission_view(request):
    user = get_user_matchdict_checked(request)
    resource = get_resource_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, resource)
    return delete_user_resource_permission(perm_name, resource, user.id, request.db)


def get_user_services_runner(request, inherited_group_services_permissions):
    user = get_user_matchdict_checked(request)
    res_perm_dict = get_user_resources_permissions_dict(user, resource_types=['service'], db_session=request.db,
                                                        inherited_permissions=inherited_group_services_permissions)

    svc_json = {}
    for resource_id, perms in res_perm_dict.items():
        svc = models.Service.by_resource_id(resource_id=resource_id, db_session=request.db)
        if svc.type not in svc_json:
            svc_json[svc.type] = {}
        svc_json[svc.type][svc.resource_name] = format_service(svc, perms)

    return valid_http(httpSuccess=HTTPOk, detail="Get user services successful", content={u'services': svc_json})


@view_config(route_name=UserServicesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_services_view(request):
    return get_user_services_runner(request, inherited_group_services_permissions=False)


@view_config(route_name=UserInheritedServicesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_inherited_services_view(request):
    return get_user_services_runner(request, inherited_group_services_permissions=True)


def get_user_service_permissions_runner(request, inherited_permissions):
    user = get_user_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perms = evaluate_call(lambda: get_user_service_permissions(service=service, user=user, db_session=request.db,
                                                               inherited_permissions=inherited_permissions),
                          fallback=lambda: request.db.rollback(), httpError=HTTPNotFound,
                          msgOnFail="Could not find permissions using specified `service_name` and `user_name`",
                          content={u'service_name': str(service.resource_name), u'user_name': str(user.user_name)})
    message_inherit = ' inherited ' if inherited_permissions else ' '
    return valid_http(httpSuccess=HTTPOk, detail="Get user service{}permissions successful".format(message_inherit),
                      content={u'permission_names': perms})


@view_config(route_name=UserServicePermissionsAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_service_permissions_view(request):
    return get_user_service_permissions_runner(request, inherited_permissions=False)


@view_config(route_name=UserServiceInheritedPermissionsAPI.name, request_method='GET',
             permission=NO_PERMISSION_REQUIRED)
def get_user_service_inherited_permissions_view(request):
    return get_user_service_permissions_runner(request, inherited_permissions=True)


@view_config(route_name=UserServicePermissionsAPI.name, request_method='POST')
def create_user_service_permission(request):
    user = get_user_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, service)
    return create_user_resource_permission(perm_name, service, user.id, request.db)


@view_config(route_name=UserServicePermissionAPI.name, request_method='DELETE')
def delete_user_service_permission(request):
    user = get_user_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, service)
    return delete_user_resource_permission(perm_name, service, user.id, request.db)


def get_user_service_resource_permissions_runner(request, inherited_permissions):
    """
    Resource permissions a user as on a specific service

    :param request:
    :param inherited_permissions: only direct permissions if False, else resolve permissions with user and its groups.
    :return:
    """
    user = get_user_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    service_perms = get_user_service_permissions(user, service, db_session=request.db,
                                                 inherited_permissions=inherited_permissions)
    resources_perms_dict = get_user_service_resources_permissions_dict(user, service, db_session=request.db,
                                                                       inherited_permissions=inherited_permissions)
    user_svc_res_json = format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=service_perms,
        resources_perms_dict=resources_perms_dict,
        display_all=False
    )
    return valid_http(httpSuccess=HTTPOk, detail="Get user service resources successful",
                      content={u'service': user_svc_res_json})


@view_config(route_name=UserServiceResourcesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_service_resources_view(request):
    return get_user_service_resource_permissions_runner(request, inherited_permissions=False)


@view_config(route_name=UserServiceInheritedResourcesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_service_inherited_resources_view(request):
    return get_user_service_resource_permissions_runner(request, inherited_permissions=True)
