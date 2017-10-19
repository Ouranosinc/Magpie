from magpie import *
import models
from api_except import *
from services import service_type_dico
from models import resource_type_dict
from management.service.service import format_service, format_service_resources
from models import resource_tree_service
from pyramid.interfaces import IAuthenticationPolicy


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

    return valid_http(httpSuccess=HTTPCreated, detail="User successfully added to db")


@view_config(route_name='users', request_method='POST')
def create_user_view(request):
    user_name = get_multiformat_post(request, 'user_name')
    email = get_multiformat_post(request, 'email')
    password = get_multiformat_post(request, 'password')
    group_name = get_multiformat_post(request, 'group_name')
    verify_param(user_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `user_name` value specified")
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
                                   httpError=HTTPForbidden, msgOnFail="Get user query refused by db")
    return valid_http(httpSuccess=HTTPOk, detail="Get users successful", content={'user_names': user_name_list})


def get_group_matchdict_checked(request, group_name_key='group_name'):
    group_name = request.matchdict.get(group_name_key)
    verify_param(group_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid group name specified using key '" + str(group_name_key) + "'")
    group = evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=request.db),
                          fallback=lambda: request.db.rollback(),
                          httpError=HTTPForbidden, msgOnFail="Group query by name refused by db")
    verify_param(group, notNone=True, httpError=HTTPNotFound, msgOnFail="Group name not found in db")
    return group


def get_user_matchdict_checked(request, user_name_key='user_name'):
    user_name = request.matchdict.get(user_name_key)
    verify_param(user_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid user name specified using key '" + str(user_name_key) + "'")
    return get_user(request, user_name)


def get_user(request, user_name_or_token):
    if len(user_name_or_token) > 20:
        authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
        user_id = get_userid_by_token(user_name_or_token, authn_policy)
        user = evaluate_call(lambda: UserService.by_id(user_id, db_session=request.db),
                             fallback=lambda: request.db.rollback(),
                             httpError=HTTPForbidden, msgOnFail="User id query refused by db")
        verify_param(user, notNone=True, httpError=HTTPNotFound, msgOnFail="User id not found in db")
        return user
    elif user_name_or_token == LOGGED_USER:
        curr_user = request.user
        if curr_user:
            return curr_user
        else:
            anonymous = evaluate_call(lambda: UserService.by_user_name(ANONYMOUS_USER, db_session=request.db),
                                      fallback=lambda: request.db.rollback(),
                                      httpError=HTTPForbidden, msgOnFail="Anonymous user query refused by db")
            verify_param(anonymous, notNone=True, httpError=HTTPNotFound, msgOnFail="Anonymous user not found in db")
            return anonymous
    else:
        user = evaluate_call(lambda: UserService.by_user_name(user_name_or_token, db_session=request.db),
                             fallback=lambda: request.db.rollback(),
                             httpError=HTTPForbidden, msgOnFail="User name query refused by db")
        verify_param(user, notNone=True, httpError=HTTPNotFound, msgOnFail="User name not found in db")
        return user


def get_userid_by_token(token, authn_policy):
    cookie_helper = authn_policy.cookie
    cookie = token
    if cookie is None:
        return None
    remote_addr = '0.0.0.0'

    timestamp, userid, tokens, user_data = cookie_helper.parse_ticket(
        cookie_helper.secret,
        cookie,
        remote_addr,
        cookie_helper.hashalg
    )
    return userid


@view_config(route_name='user', request_method='GET')
def get_user_view(request):
    user = get_user_matchdict_checked(request)
    json_response = {'user_name': user.user_name,
                     'email': user.email,
                     'group_names': [group.group_name for group in user.groups]}
    return valid_http(httpSuccess=HTTPOk, detail="Get user", content=json_response)


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
    return valid_http(httpSuccess=HTTPOk, detail="User deleted")


@view_config(route_name='user_groups', request_method='GET')
def get_user_groups(request):
    user = get_user_matchdict_checked(request)
    verify_param(user, notNone=True, httpError=HTTPNotFound, msgOnFail="User name not found in db")
    db = request.db
    group_names = evaluate_call(lambda: [group.group_name for group in user.groups], fallback=lambda: db.rollback(),
                                httpError=HTTPInternalServerError, msgOnFail="Failed to extract groups from user")
    return valid_http(httpSuccess=HTTPOk, detail="Get user groups", content={'group_names': group_names})


@view_config(route_name='user_group', request_method='POST')
def assign_user_group(request):
    user_name = request.matchdict.get('user_name')
    group_name = request.matchdict.get('group_name')
    db = request.db
    try:
        user = UserService.by_user_name(user_name, db_session=db)
        if user is None:
            raise HTTPNotFound(detail='user not found')
        cur_group = GroupService.by_group_name(group_name, db_session=db)
        if cur_group is None:
            raise HTTPNotFound(detail='group not found')
        new_user_group = models.UserGroup(group_id=cur_group.id, user_id=user.id)
        db.add(new_user_group)
        
    except:
        db.rollback()
        raise HTTPConflict(detail='this user already belongs to this group')

    return HTTPCreated()


@view_config(route_name='user_group', request_method='DELETE')
def delete_user_group(request):
    user_name = request.matchdict.get('user_name')
    group_name = request.matchdict.get('group_name')

    try:
        db = request.db
        user = UserService.by_user_name(user_name, db_session=db)
        if user is None:
            raise HTTPNotFound(detail='user not found')
        group = GroupService.by_group_name(group_name, db_session=db)
        if group is None:
            raise HTTPNotFound(detail='group not found')

        db.query(models.UserGroup)\
            .filter(models.UserGroup.user_id == user.id)\
            .filter(models.UserGroup.group_id == group.id)\
            .delete()
        

    except:
        db.rollback()
        raise HTTPConflict(detail='this user does not belong to this group')

    return HTTPOk()


def get_user_resource_permissions(user, resource, db_session):
    if resource.owner_user_id == user.id:
        permission_names = resource_type_dict[resource.type].permission_names
    else:
        permission_names = [permission.perm_name for permission in resource.perms_for_user(user, db_session=db_session)]
    return permission_names


def get_user_service_permissions(user, service, db_session):
    if service.owner_user_id == user.id:
        permission_names = service_type_dico[service.type].permission_names
    else:
        permission_names = [permission.perm_name for permission in service.perms_for_user(user, db_session=db_session)]
    return permission_names


def get_user_resources_permissions_dict(user, db_session,resource_types=None, resource_ids=None):
    db = db_session
    if user is None:
        raise HTTPBadRequest(detail='This user does not exist')
    resource_permission_tuple = user.resources_with_possible_perms(resource_ids=resource_ids, resource_types=resource_types, db_session=db)
    resources_permissions_dict = {}
    for tuple in resource_permission_tuple:
        if tuple.resource.resource_id not in resources_permissions_dict:
            resources_permissions_dict[tuple.resource.resource_id] = [tuple.perm_name]
        else:
            resources_permissions_dict[tuple.resource.resource_id].append(tuple.perm_name)

    return resources_permissions_dict


def get_user_service_resources_permissions_dict(user, service, db_session):
    resources_under_service = resource_tree_service.from_parent_deeper(parent_id=service.resource_id, db_session=db_session)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    return get_user_resources_permissions_dict(user, db_session, resource_types=None, resource_ids=resource_ids)


@view_config(route_name='user_resources', request_method='GET')
def get_user_resources_view(request):
    user_name = request.matchdict.get('user_name')
    db = request.db
    #user = UserService.by_user_name(user_name=user_name, db_session=db)
    user = get_user(request, user_name_or_token=user_name)
    if user is None:
        raise HTTPBadRequest(detail='This user does not exist')

    services_permissions_dict = get_user_resources_permissions_dict(user,
                                                                    resource_types=['service'],
                                                                    db_session=request.db)

    json_response = {}

    for curr_service in models.Service.all(db_session=db):
        service_perms = get_user_service_permissions(user=user, service=curr_service, db_session=db)
        service_name = curr_service.resource_name
        service_type = curr_service.type
        if service_type not in json_response:
            json_response[service_type] = {}

        resources_perms_dico = get_user_service_resources_permissions_dict(user=user,
                                                                           service=curr_service,
                                                                           db_session=db)
        json_response[service_type][service_name] = format_service_resources(
                curr_service,
                db_session=db,
                service_perms=service_perms,
                resources_perms_dico=resources_perms_dico,
                display_all=False
            )


    json_response = {'resources': json_response}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='user_resource_permissions', request_method='GET')
def get_user_resource_permissions_view(request):
    user_name = request.matchdict.get('user_name')
    resource_id = request.matchdict.get('resource_id')
    db = request.db
    resource = ResourceService.by_resource_id(resource_id, db)
    #user = UserService.by_user_name(user_name=user_name, db_session=db)
    user = get_user(request, user_name_or_token=user_name)

    permission_names = get_user_resource_permissions(resource=resource, user=user, db_session=db)
    return HTTPOk(
        body=json.dumps({'permission_names': permission_names}),
        content_type='application/json'
    )


def create_user_resource_permission(permission_name, resource_id, user_id, db_session):
    try:
        new_permission = models.UserResourcePermission(resource_id=resource_id, user_id=user_id)
        new_permission.perm_name = permission_name
        db_session.add(new_permission)
    except:
        db_session.rollback()
        raise HTTPConflict('This permission on that service already exists for that user')
    return HTTPCreated()


@view_config(route_name='user_resource_permissions', request_method='POST')
def create_user_resource_permission_view(request):
    user_name = request.matchdict.get('user_name')
    resource_id = request.matchdict.get('resource_id')
    permission_name = get_multiformat_post(request, 'permission_name')
    db = request.db

    user = UserService.by_user_name(user_name=user_name, db_session=db)
    resource = ResourceService.by_resource_id(resource_id, db)
    if resource is None or user is None:
        raise HTTPNotFound(detail='this user/resource does not exist')
    if permission_name not in resource_type_dict[resource.resource_type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that resource')

    return create_user_resource_permission(permission_name, resource_id, user.id, db)


@view_config(route_name='user_resource_permission', request_method='DELETE')
def delete_user_resource_permission_view(request):
    user_name = request.matchdict.get('user_name')
    resource_id = request.matchdict.get('resource_id')
    permission_name = request.matchdict.get('permission_name')

    db = request.db
    #user = UserService.by_user_name(user_name=user_name, db_session=db)
    user = get_user(request, user_name_or_token=user_name)
    resource = ResourceService.by_resource_id(resource_id, db)
    if resource is None or user is None:
        raise HTTPNotFound(detail='this user/resource does not exist')
    if permission_name not in resource_type_dict[resource.resource_type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that resource')

    return delete_user_resource_permission(permission_name,
                                           resource_id,
                                           user.id,
                                           db)


@view_config(route_name='user_services', request_method='GET')
def get_user_services_view(request):
    user_name = request.matchdict.get('user_name')
    db = request.db
    # user = UserService.by_user_name(user_name=user_name, db_session=db)
    user = get_user(request, user_name_or_token=user_name)

    json_response = {}

    resources_permissions_dict = get_user_resources_permissions_dict(user,
                                                                     resource_types=['service'],
                                                                     db_session=request.db)

    for resource_id, perms in resources_permissions_dict.items():
        curr_service = models.Service.by_resource_id(resource_id=resource_id, db_session=db)
        service_type = curr_service.type
        service_name = curr_service.resource_name
        if service_type not in json_response:
            json_response[service_type] = {}
        json_response[service_type][service_name] = format_service(curr_service, perms)

    return HTTPOk(
        body=json.dumps({'services': json_response}),
        content_type='application/json'
    )



@view_config(route_name='user_service_permissions', request_method='GET')
def get_user_service_permissions_view(request):
    user_name = request.matchdict.get('user_name')
    service_name = request.matchdict.get('service_name')

    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    # user = UserService.by_user_name(user_name=user_name, db_session=db)
    user = get_user(request, user_name_or_token=user_name)

    if service is None or user is None:
        raise HTTPNotFound(detail='this service/user does not exist')

    permission_names = get_user_service_permissions(service=service, user=user, db_session=db)
    json_response = {service.resource_name: format_service(service)}
    json_response[service.resource_name]['permission_names'] = permission_names
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='user_service_permissions', request_method='POST')
def create_user_service_permission(request):
    user_name = request.matchdict.get('user_name')
    service_name = request.matchdict.get('service_name')
    permission_name = get_multiformat_post(request, 'permission_name')

    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    # user = UserService.by_user_name(user_name=user_name, db_session=db)
    user = get_user(request, user_name_or_token=user_name)

    if service is None or user is None:
        raise HTTPNotFound(detail='this service/user does not exist')
    if permission_name not in service_type_dico[service.type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that service')

    return create_user_resource_permission(permission_name=permission_name,
                                           resource_id=service.resource_id,
                                           user_id=user.id,
                                           db_session=db)


def delete_user_resource_permission(permission_name, resource_id, user_id, db_session):
    try:
        permission_to_delete = UserResourcePermissionService.get(user_id, resource_id, permission_name, db_session)
        db_session.delete(permission_to_delete)
    except:
        db_session.rollback()
        raise HTTPNotFound(detail="This permission on that service does not exist for that user")

    return HTTPOk()


@view_config(route_name='user_service_permission', request_method='DELETE')
def delete_user_service_permission(request):
    user_name = request.matchdict.get('user_name')
    service_name = request.matchdict.get('service_name')
    permission_name = request.matchdict.get('permission_name')

    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    # user = UserService.by_user_name(user_name=user_name, db_session=db)
    user = get_user(request, user_name_or_token=user_name)

    if service is None or user is None:
        raise HTTPNotFound(detail='this service/user does not exist')
    if permission_name not in service_type_dico[service.type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that service')

    return delete_user_resource_permission(permission_name,
                                           service.resource_id,
                                           user.id,
                                           db)


@view_config(route_name='user_service_resources', request_method='GET')
def get_user_service_resources_view(request):
    user_name = request.matchdict.get('user_name')
    service_name = request.matchdict.get('service_name')
    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    #user = UserService.by_user_name(user_name, db_session=db)
    user = get_user(request, user_name_or_token=user_name)

    if service is None or user is None:
        raise HTTPNotFound(detail='this user/resource does not exist')

    service_perms = get_user_service_permissions(user=user, service=service, db_session=db)

    resources_perms_dico = get_user_service_resources_permissions_dict(user=user,
                                                                       service=service,
                                                                       db_session=db)
    json_response = format_service_resources(
        service=service,
        db_session=db,
        service_perms=service_perms,
        resources_perms_dico=resources_perms_dico,
        display_all=False
    )


    return HTTPOk(
        body=json.dumps({'service': json_response}),
        content_type='application/json'
    )





