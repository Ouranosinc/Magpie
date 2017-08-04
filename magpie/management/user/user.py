from magpie import *
import models
from services import service_type_dico
from models import resource_type_dico
from management.service.resource import get_resource_info
from models import resource_tree_service

@view_config(route_name='users', request_method='POST')
def create_user(request):
    user_name = request.POST.get('user_name')
    email = request.POST.get('email')
    password = request.POST.get('password')
    group_name = request.POST.get('group_name')
    try:
        db = request.db
        new_user = models.User(user_name=user_name, email=email)
        new_user.set_password(password)
        new_user.regenerate_security_code()
        db.add(new_user)
        db.commit()

        group = GroupService.by_group_name(group_name, db_session=db)
        group_entry = models.UserGroup(group_id=group.id, user_id=new_user.id)
        db.add(group_entry)
        db.commit()
    except:
        raise HTTPConflict(detail='this user already exists')

    return HTTPCreated()


@view_config(route_name='users', request_method='GET')
def get_users(request):
    user_name_list = [user.user_name for user in models.User.all(db_session=request.db)]
    json_response = {'user_names': user_name_list}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='user', request_method='GET')
def get_user(request):
    user_name = request.matchdict.get('user_name')
    try:
        db = request.db
        user = UserService.by_user_name(user_name, db_session=db)
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
        db.commit()

    except:
        db.rollback()
        raise HTTPNotFound(detail="This user does not exist")

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

from models import get_all_resource_permission_names
def get_user_resources(request, resource_types):
    user_name = request.matchdict.get('user_name')
    db = request.db
    user = UserService.by_user_name(user_name=user_name, db_session=db)
    if user is None:
        raise HTTPBadRequest(detail='This user does not exist')
    all_resource_permission = get_all_resource_permission_names()
    resources = UserService.resources_with_perms(user, resource_types=resource_types, perms=all_resource_permission,
                                                 db_session=db).all()

    resource_available_dico = {}
    for resource in resources:
        resource_available_dico[resource.resource_id] = get_resource_info(resource.resource_id, db)
        resource_available_dico[resource.resource_id]['permission_names'] = [
            'ALL_PERMISSIONS' if permission.perm_name is ALL_PERMISSIONS
            else permission.perm_name
            for permission in resource.perms_for_user(user)]


    return HTTPOk(
        body=json.dumps({'resources': resource_available_dico}),
        content_type='application/json'
    )


@view_config(route_name='user_resources', request_method='GET')
def get_user_resources_view(request):
    return get_user_resources(request, resource_types=None)


from models import get_all_resource_permission_names
@view_config(route_name='user_resources_type', request_method='GET')
def get_user_resources_types_view(request):
    return get_user_resources(request, resource_types=[request.matchdict.get('resource_type')])


def get_user_resource_permissions(resource, user):
    if resource is None or user is None:
        raise HTTPNotFound(detail='this service/user does not exist')

    if resource.owner_user_id == user.id:
        permission_names = ['ALL_PERMISSIONS']
    else:
        user_res_permission = resource.perms_for_user(user)
        permission_names = [permission.perm_name for permission in user_res_permission]
        if ALL_PERMISSIONS in permission_names:
            permission_names = ['ALL_PERMISSIONS']

    return HTTPOk(
        body=json.dumps({'permission_names': permission_names}),
        content_type='application/json'
    )


@view_config(route_name='user_resource_permissions', request_method='GET')
def get_user_resource_permissions_view(request):
    user_name = request.matchdict.get('user_name')
    resource_id = request.matchdict.get('resource_id')
    db = request.db
    resource = ResourceService.by_resource_id(resource_id, db)
    user = UserService.by_user_name(user_name=user_name, db_session=db)

    return get_user_resource_permissions(resource=resource, user=user)

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
    permission_name = request.POST.get('permission_name')
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
    user = UserService.by_user_name(user_name=user_name, db_session=db)
    resource = ResourceService.by_resource_id(resource_id, db)
    if resource is None or user is None:
        raise HTTPNotFound(detail='this user/resource does not exist')
    if permission_name not in resource_type_dico[resource.resource_type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that resource')

    return delete_user_resource_permission(permission_name,
                                           resource_id,
                                           user.id,
                                           db)


from services import get_all_service_permission_names
@view_config(route_name='user_services', request_method='GET')
def get_user_services(request):
    user_name = request.matchdict.get('user_name')
    db = request.db
    user = UserService.by_user_name(user_name=user_name, db_session=db)
    all_service_permission = get_all_service_permission_names()

    services = UserService.resources_with_perms(user, perms=all_service_permission, db_session=db).all()
    service_available_dico = {}
    for service in services:
        service_available_dico[service.resource_id] = get_resource_info(service.resource_id, db)
        service_available_dico[service.resource_id]['permission_names'] = ['ALL_PERMISSIONS' if permission.perm_name is ALL_PERMISSIONS
                                                                           else permission.perm_name
                                                                           for permission in service.perms_for_user(user)]

    return HTTPOk(
        body=json.dumps({'services': service_available_dico}),
        content_type='application/json'
    )




@view_config(route_name='user_service_permissions', request_method='GET')
def get_user_service_permissions(request):
    user_name = request.matchdict.get('user_name')
    service_name = request.matchdict.get('service_name')

    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    user = UserService.by_user_name(user_name=user_name, db_session=db)

    return get_user_resource_permissions(resource=service, user=user, db_session=db)




@view_config(route_name='user_service_permissions', request_method='POST')
def create_user_service_permission(request):
    user_name = request.matchdict.get('user_name')
    service_name = request.matchdict.get('service_name')
    permission_name = request.POST.get('permission_name')

    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    user = UserService.by_user_name(user_name=user_name, db_session=db)
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
    user = UserService.by_user_name(user_name=user_name, db_session=db)
    if service is None or user is None:
        raise HTTPNotFound(detail='this service/user does not exist')
    if permission_name not in service_type_dico[service.type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that service')

    return delete_user_resource_permission(permission_name,
                                           service.resource_id,
                                           user.id,
                                           db)



@view_config(route_name='user_service_resources', request_method='GET')
def get_user_service_resources(request):
    user_name = request.matchdict.get('user_name')
    service_name = request.matchdict.get('service_name')
    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    user = UserService.by_user_name(user_name, db_session=db)
    if service is None or user is None:
        raise HTTPNotFound(detail='this user/resource does not exist')

    tree_struct = resource_tree_service.from_parent_deeper(service.resource_id, db_session=db)
    children_ids = []
    for node in tree_struct:
        children_ids.append(node.Resource.resource_id)

    resource_info_dic = {}
    if children_ids:
        resources = user.resources_with_possible_perms(resource_ids=children_ids, db_session=db)
        for resource_tuple in resources:
            if resource_tuple.resource.resource_id in resource_info_dic.keys():
                resource_info_dic[resource_tuple.resource.resource_id]['permission_names'].append(resource_tuple.perm_name)
            else:
                resource_info = get_resource_info(resource_tuple.resource.resource_id, db_session=db)
                resource_info['permission_names'] = [resource_tuple.perm_name]
                resource_info_dic[resource_tuple.resource.resource_id] = resource_info

    return HTTPOk(
        body=json.dumps({'resources': resource_info_dic}),
        content_type='application/json'
    )



