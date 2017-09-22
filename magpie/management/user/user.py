from magpie import *
import models
from services import service_type_dico
from models import resource_type_dico
from management.service.service import format_service, format_service_resources
from models import resource_tree_service
from pyramid.interfaces import IAuthenticationPolicy


def create_user(user_name, password, email, group_name, db_session):
    """
    When a user is created, he is automatically assigned to a group with the same name.
    He is also added to a default group specified by group_name.
    It is then easier to check permission on resource a user has:
    Check all permission inherited from group: GET /users/user_name/permissions
    Check direct permission of user: GET /groups/user_name/permissions

    :param request: 
    :return: 
    """

    db = db_session
    # Check if group already exist
    group = GroupService.by_group_name(group_name, db_session=db)
    if not group:
        raise HTTPNotFound(detail='This group does not exist')

    # Create new_group associated to user
    new_group = GroupService.by_group_name(group_name=user_name, db_session=db)
    new_user = UserService.by_user_name(user_name=user_name, db_session=db)
    if new_group or new_user:
        raise HTTPConflict(detail="This user already exist")

    try:
        new_group = models.Group(group_name=user_name)
        db.add(new_group)
        db.commit()
    except Exception, e:
        db.rollback()
        raise HTTPConflict(detail=e.message)

    try:
        new_user = models.User(user_name=user_name, email=email)
        if password:
            new_user.set_password(password)
        new_user.regenerate_security_code()
        db.add(new_user)
        db.commit()
    except Exception, e:
        db.rollback()
        new_group.delete(db_session=db)
        db.commit()
        raise HTTPConflict(detail=e.message)

    # Assign user to default group and own group
    try:
        group_entry = models.UserGroup(group_id=group.id, user_id=new_user.id)
        db.add(group_entry)

        new_group_entry = models.UserGroup(group_id=new_group.id, user_id=new_user.id)
        db.add(new_group_entry)

        db.commit()

    except:
        db.rollback()
        raise HTTPConflict(
            detail='No way to add ' + user_name + ' to group ' + group_name + ', maybe this group does not exist'
        )

    return HTTPCreated()


@view_config(route_name='users', request_method='POST')
def create_user_view(request):


    user_name = get_multiformat_post(request, 'user_name')
    email = get_multiformat_post(request, 'email')
    password = get_multiformat_post(request, 'password')
    group_name = get_multiformat_post(request, 'group_name')

    db = request.db
    return create_user(user_name, password, email, group_name, db_session=db)


@view_config(route_name='users', request_method='GET')
def get_users(request):
    user_name_list = [user.user_name for user in models.User.all(db_session=request.db)]
    json_response = {'user_names': user_name_list}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


def get_user(request, user_name_or_token):
    try:
        if len(user_name_or_token) > 20:
            authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
            user_id = get_userid_by_token(user_name_or_token, authn_policy)
            return UserService.by_id(user_id, db_session=request.db)
        else:
            return UserService.by_user_name(user_name_or_token, db_session=request.db)
    except Exception, e:
        raise HTTPNotFound(detail=e.message)


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
    user_name = request.matchdict.get('user_name')
    try:
        #user = UserService.by_user_name(user_name, db_session=db)
        user = get_user(request, user_name)
        json_response = {'user_name': user.user_name,
                         'email': user.email,
                         'group_names': [group.group_name for group in user.groups]}
    except:
        raise HTTPNotFound(detail='User not found')

    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='user', request_method='DELETE')
def delete_user(request):
    user_name = request.matchdict.get('user_name')
    try:
        db = request.db
        user = UserService.by_user_name(user_name, db_session=db)
        db.delete(user)

        group_user = GroupService.by_group_name(user_name, db_session=db)
        db.delete(group_user)

        db.commit()

    except Exception, e:
        db.rollback()
        raise HTTPNotFound(detail=e.message)

    return HTTPOk()


@view_config(route_name='user_groups', request_method='GET')
def get_user_groups(request):
    user_name = request.matchdict.get('user_name')
    try:
        db = request.db
        user = UserService.by_user_name(user_name, db_session=db)
        json_response = {'group_names': [group.group_name for group in user.groups]}
    except:
        db.rollback()
        raise HTTPNotFound(detail="This user does not exist")
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )

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
        db.commit()
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
        permission_names = resource_type_dico[resource.type].permission_names
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
        db_session.commit()
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
    if permission_name not in resource_type_dico[resource.resource_type].permission_names:
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
    if permission_name not in resource_type_dico[resource.resource_type].permission_names:
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
        db_session.commit()
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





