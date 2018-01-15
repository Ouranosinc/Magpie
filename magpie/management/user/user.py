from magpie import *
from api_except import *
from api_requests import *
from services import service_type_dict
from models import resource_type_dict, resource_tree_service
from management.service.service import format_service, format_service_resources


def rollback_delete(db, entry):
    db.rollback()
    entry.delete(db_session=db)


def create_user(user_name, password, email, group_name, db_session):
    """
    When a user is created, he is automatically assigned to a group with the same name.
    He is also added to a default group specified by group_name.
    It is then easier to check permission on resource a user has:
    Check all permission inherited from group: GET /users/user_name/permissions
    Check direct permission of user: GET /groups/user_name/permissions

    :return: `HTTPCreated` if successful
    :raise `HTTPNotAcceptable`:
    :raise `HTTPConflict`:
    :raise `HTTPForbidden`:
    """
    db = db_session
    # Check if group already exist
    group = evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=db),
                          httpError=HTTPForbidden, msgOnFail="Group query was refused by db")
    verify_param(group, notNone=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Group for new user already exists")

    # Create new_group associated to user
    group_check = evaluate_call(lambda: GroupService.by_group_name(group_name=user_name, db_session=db),
                                httpError=HTTPForbidden, msgOnFail="Group check query was refused by db")
    user_check = evaluate_call(lambda: UserService.by_user_name(user_name=user_name, db_session=db),
                               httpError=HTTPForbidden, msgOnFail="User check query was refused by db")
    verify_param(group_check, isNone=True, httpError=HTTPConflict,
                 msgOnFail="User name matches an already existing group name")
    verify_param(user_check, isNone=True, httpError=HTTPConflict,
                 msgOnFail="User name matches an already existing user name")
    group_model = models.Group(group_name=user_name)
    evaluate_call(lambda: db.add(group_model), fallback=lambda: rollback_delete(db, group_model),
                  httpError=HTTPForbidden, msgOnFail="Failed to add group to db")

    # Create user with specified name and newly created group
    user_model = models.User(user_name=user_name, email=email)
    if password:
        user_model.set_password(password)
        user_model.regenerate_security_code()
    evaluate_call(lambda: db.add(user_model), fallback=lambda: rollback_delete(db, group_model),
                  httpError=HTTPForbidden, msgOnFail="Failed to add user to db")

    # Assign user to default group and own group
    new_user = evaluate_call(lambda: UserService.by_user_name(user_name, db_session=db),
                             httpError=HTTPForbidden, msgOnFail="New user query was refused by db")
    group_entry = models.UserGroup(group_id=group.id, user_id=new_user.id)
    evaluate_call(lambda: db.add(group_entry), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Failed to add user-group to db")
    new_group = evaluate_call(lambda: GroupService.by_group_name(user_name, db_session=db),
                              httpError=HTTPForbidden, msgOnFail="New group query was refused by db")
    new_group_entry = models.UserGroup(group_id=new_group.id, user_id=new_user.id)
    evaluate_call(lambda: db.add(new_group_entry), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Failed to add user-group to db")

    return valid_http(httpSuccess=HTTPCreated, detail="Add user to db successful")


@view_config(route_name='users', request_method='POST')
def create_user_view(request):
    user_name = get_multiformat_post(request, 'user_name')
    email = get_multiformat_post(request, 'email')
    password = get_multiformat_post(request, 'password')
    group_name = get_multiformat_post(request, 'group_name')
    verify_param(user_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `user_name` value specified")
    verify_param(len(user_name), isIn=True, httpError=HTTPNotAcceptable,
                 paramCompare=range(1, 1 + USER_NAME_MAX_LENGTH),
                 msgOnFail="Invalid `user_name` length specified " +
                           "(>{length} characters)".format(length=USER_NAME_MAX_LENGTH))
    verify_param(email, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `email` value specified")
    verify_param(password, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `password` value specified")
    verify_param(group_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `group_name` value specified")
    verify_param(user_name, paramCompare=[LOGGED_USER], notIn=True, httpError=HTTPConflict,
                 msgOnFail="Invalid `user_name` already logged in")
    return create_user(user_name, password, email, group_name, db_session=request.db)


@view_config(route_name='users', request_method='GET')
def get_users(request):
    user_name_list = evaluate_call(lambda: [user.user_name for user in models.User.all(db_session=request.db)],
                                   fallback=lambda: request.db.rollback(),
                                   httpError=HTTPForbidden, msgOnFail="Get users query refused by db")
    return valid_http(httpSuccess=HTTPOk, detail="Get users successful", content={u'user_names': user_name_list})


@view_config(route_name='user', request_method='GET')
def get_user_view(request):
    user = get_user_matchdict_checked(request)
    json_response = {u'user_name': user.user_name,
                     u'email': user.email,
                     u'group_names': [group.group_name for group in user.groups]}
    return valid_http(httpSuccess=HTTPOk, detail="Get user successful", content=json_response)


@view_config(route_name='user', request_method='DELETE')
def delete_user(request):
    user = get_user_matchdict_checked(request)
    db = request.db
    evaluate_call(lambda: db.delete(user), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Delete user by name refused by db")
    user_group = evaluate_call(lambda: GroupService.by_group_name(user.user_name, db_session=db),
                               fallback=lambda: db.rollback(),
                               httpError=HTTPNotFound, msgOnFail="Could not find user-group in db")
    evaluate_call(lambda: db.delete(user_group), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Delete user-group refused by db")
    return valid_http(httpSuccess=HTTPOk, detail="Delete user successful")


def get_user_groups_checked(request, user):
    verify_param(user, notNone=True, httpError=HTTPNotFound, msgOnFail="User name not found in db")
    db = request.db
    group_names = evaluate_call(lambda: [group.group_name for group in user.groups], fallback=lambda: db.rollback(),
                                httpError=HTTPInternalServerError, msgOnFail="Failed to obtain groups of user")
    return group_names


@view_config(route_name='user_groups', request_method='GET')
def get_user_groups(request):
    user = get_user_matchdict_checked(request)
    group_names = get_user_groups_checked(request, user)
    return valid_http(httpSuccess=HTTPOk, detail="Get user groups successful", content={u'group_names': group_names})


@view_config(route_name='user_group', request_method='POST')
def assign_user_group(request):
    user = get_user_matchdict_checked(request)
    group = get_group_matchdict_checked(request)
    new_user_group = models.UserGroup(group_id=group.id, user_id=user.id)
    db = request.db
    evaluate_call(lambda: db.add(new_user_group), fallback=lambda: db.rollback(),
                  httpError=HTTPConflict, msgOnFail="User already belongs to this group",
                  content={u'user_name': user.user_name, u'group_name': group.group_name})
    return valid_http(httpSuccess=HTTPCreated, detail="Create user-group assignation successful")


@view_config(route_name='user_group', request_method='DELETE')
def delete_user_group(request):
    user = get_user_matchdict_checked(request)
    group = get_group_matchdict_checked(request)
    db = request.db

    def del_usr_grp(usr, grp):
        db.query(models.UserGroup) \
            .filter(models.UserGroup.user_id == usr.id) \
            .filter(models.UserGroup.group_id == grp.id) \
            .delete()

    evaluate_call(lambda: del_usr_grp(user, group), fallback=lambda: db.rollback(),
                  httpError=HTTPNotAcceptable, msgOnFail="Invalid user-group combination for delete",
                  content={u'user_name': user.user_name, u'group_name': group.group_name})
    return valid_http(httpSuccess=HTTPOk, detail="Delete user-group successful")


def get_user_resource_permissions(user, resource, db_session):
    if resource.owner_user_id == user.id:
        permission_names = resource_type_dict[resource.type].permission_names
    else:
        permission_names = [permission.perm_name for permission in resource.perms_for_user(user, db_session=db_session)]
    return permission_names


def get_user_service_permissions(user, service, db_session):
    if service.owner_user_id == user.id:
        permission_names = service_type_dict[service.type].permission_names
    else:
        permission_names = [permission.perm_name for permission in service.perms_for_user(user, db_session=db_session)]
    return permission_names


def get_user_resources_permissions_dict(user, db_session, resource_types=None, resource_ids=None):
    verify_param(user, notNone=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid user specified to obtain resource permissions")
    resource_permission_tuple = user.resources_with_possible_perms(resource_ids=resource_ids,
                                                                   resource_types=resource_types, db_session=db_session)
    resources_permissions_dict = {}
    for res_perm in resource_permission_tuple:
        if res_perm.resource.resource_id not in resources_permissions_dict:
            resources_permissions_dict[res_perm.resource.resource_id] = [res_perm.perm_name]
        else:
            resources_permissions_dict[res_perm.resource.resource_id].append(res_perm.perm_name)

    return resources_permissions_dict


def get_user_service_resources_permissions_dict(user, service, db_session):
    resources_under_service = resource_tree_service.from_parent_deeper(parent_id=service.resource_id,
                                                                       db_session=db_session)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    return get_user_resources_permissions_dict(user, db_session, resource_types=None, resource_ids=resource_ids)


@view_config(route_name='user_resources', request_method='GET')
def get_user_resources_view(request):
    user = get_user_matchdict_checked(request)
    db = request.db

    def build_json_user_resource_tree(usr):
        json_res = {}
        for svc in models.Service.all(db_session=db):
            svc_perms = get_user_service_permissions(user=usr, service=svc, db_session=db)
            if svc.type not in json_res:
                json_res[svc.type] = {}
            res_perms_dict = get_user_service_resources_permissions_dict(user=usr, service=svc, db_session=db)
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


@view_config(route_name='user_resource_permissions', request_method='GET')
def get_user_resource_permissions_view(request):
    user = get_user_matchdict_checked(request)
    res = get_resource_matchdict_checked(request, 'resource_id')
    perm_names = get_user_resource_permissions(resource=res, user=user, db_session=request.db)
    return valid_http(httpSuccess=HTTPOk, detail="Get user resource permissions successful",
                      content={u'permission_names': perm_names})


def create_user_resource_permission(permission_name, resource_id, user_id, db_session):
    new_perm = models.UserResourcePermission(resource_id=resource_id, user_id=user_id)
    verify_param(new_perm, notNone=True, httpError=HTTPNotAcceptable,
                 content={u'resource_id': str(resource_id), u'user_id': str(user_id)},
                 msgOnFail="Failed to create permission using specified `resource_id` and `user_id`")
    new_perm.perm_name = permission_name
    evaluate_call(lambda: db_session.add(new_perm), fallback=lambda: db_session.rollback(),
                  httpError=HTTPConflict, msgOnFail="Permission already exist on service for user, cannot add to db",
                  content={u'resource_id': resource_id, u'user_id': user_id, u'permission_name': permission_name})
    return valid_http(httpSuccess=HTTPCreated, detail="Create user resource permission successful",
                      content={u'resource_id': resource_id})


@view_config(route_name='user_resource_permissions', request_method='POST')
def create_user_resource_permission_view(request):
    user = get_user_matchdict_checked(request)
    res = get_resource_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, res)
    verify_param(perm_name, paramCompare=resource_type_dict[res.resource_type].permission_names, isIn=True,
                 httpError=HTTPBadRequest, msgOnFail="Permission not allowed for that resource type")
    return create_user_resource_permission(perm_name, res.resource_id, user.id, request.db)


def delete_user_resource_permission(permission_name, resource_id, user_id, db_session):
    del_perm = UserResourcePermissionService.get(user_id, resource_id, permission_name, db_session)
    evaluate_call(lambda: db_session.delete(del_perm), fallback=lambda: db_session.rollback(),
                  httpError=HTTPNotFound, msgOnFail="Could not find user resource permission to delete from db",
                  content={u'resource_id': resource_id, u'user_id': user_id, u'permission_name': permission_name})
    return valid_http(httpSuccess=HTTPOk, detail="Delete user resource permission successful")


@view_config(route_name='user_resource_permission', request_method='DELETE')
def delete_user_resource_permission_view(request):
    user = get_user_matchdict_checked(request)
    res = get_resource_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, res)
    verify_param(perm_name, paramCompare=resource_type_dict[res.resource_type].permission_names, isIn=True,
                 httpError=HTTPBadRequest, msgOnFail="Permission not allowed for that resource type")
    return delete_user_resource_permission(perm_name, res.resource_id, user.id, request.db)


@view_config(route_name='user_services', request_method='GET')
def get_user_services_view(request):
    user = get_user_matchdict_checked(request)
    res_perm_dict = get_user_resources_permissions_dict(user, resource_types=['service'], db_session=request.db)

    svc_json = {}
    for resource_id, perms in res_perm_dict.items():
        svc = models.Service.by_resource_id(resource_id=resource_id, db_session=request.db)
        if svc.type not in svc_json:
            svc_json[svc.type] = {}
        svc_json[svc.type][svc.resource_name] = format_service(svc, perms)

    return valid_http(httpSuccess=HTTPOk, detail="Get user services successful", content={u'services': svc_json})


@view_config(route_name='user_service_permissions', request_method='GET')
def get_user_service_permissions_view(request):
    user = get_user_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perms = evaluate_call(lambda: get_user_service_permissions(service=service, user=user, db_session=request.db),
                          fallback=lambda: request.db.rollback(), httpError=HTTPNotFound,
                          msgOnFail="Could not find permissions using specified `service_name` and `user_name`",
                          content={u'service_name': str(service.resource_name), u'user_name': str(user.user_name)})
    return valid_http(httpSuccess=HTTPOk, detail="Get user service permissions successful",
                      content={u'permission_names': perms})


@view_config(route_name='user_service_permissions', request_method='POST')
def create_user_service_permission(request):
    user = get_user_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, service)
    return create_user_resource_permission(perm_name, service.resource_id, user.id, request.db)


@view_config(route_name='user_service_permission', request_method='DELETE')
def delete_user_service_permission(request):
    user = get_user_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, service)
    return delete_user_resource_permission(perm_name, service.resource_id, user.id, request.db)


@view_config(route_name='user_service_resources', request_method='GET')
def get_user_service_resources_view(request):
    user = get_user_matchdict_checked(request)
    service = get_service_matchdict_checked(request)
    service_perms = get_user_service_permissions(user, service, db_session=request.db)
    resources_perms_dict = get_user_service_resources_permissions_dict(user, service, db_session=request.db)
    user_svc_res_json = format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=service_perms,
        resources_perms_dict=resources_perms_dict,
        display_all=False
    )
    return valid_http(httpSuccess=HTTPOk, detail="Get user service resources successful",
                      content={u'service': user_svc_res_json})
