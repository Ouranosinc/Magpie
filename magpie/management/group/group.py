from magpie import *
import models
from models import resource_type_dico
from management.service.resource import get_resource_info
from models import resource_tree_service

@view_config(route_name='groups', request_method='GET')
def get_groups(request):
    group_name_list = [group.group_name for group in models.Group.all(db_session=request.db)]
    json_response = {'group_names': group_name_list}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='groups', request_method='POST')
def create_group(request):
    try:
        db = request.db
        group_name = request.POST.get('group_name')
        new_group = models.Group(group_name=group_name)
        db.add(new_group)
        db.commit()
    except:
        # Group already exist
        db.rollback()
        raise HTTPConflict(detail='This name already exists')

    return HTTPCreated()


@view_config(route_name='group', request_method='DELETE')
def delete_group(request):
    group_name = request.matchdict.get('group_name')
    try:
        db = request.db
        group = GroupService.by_group_name(group_name, db_session=db)
        db.delete(group)
        db.commit()

    except:
        db.rollback()
        raise HTTPNotFound(detail="This group does not exist")

    return HTTPOk()


@view_config(route_name='group_users', request_method='GET')
def get_group_users(request):
    group_name = request.matchdict.get('group_name')
    try:
        db = request.db
        group = GroupService.by_group_name(group_name, db_session=db)
        json_response = {'user_names': [user.user_name for user in group.users]}
    except:
        raise HTTPNotFound(detail="This group does not exist")

    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='group_services', request_method='GET')
def get_group_services(request):
    json_response = get_group_resources(request, resource_types=['service'])
    return HTTPOk(
        body=json.dumps({'services': json_response}),
        content_type='application/json'
    )



from services import service_type_dico
@view_config(route_name='group_service_permissions', request_method='GET')
def get_group_service_permissions(request):
    group_name = request.matchdict.get('group_name')
    service_name = request.matchdict.get('service_name')

    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if service is None or group is None:
        raise HTTPNotFound(detail='this service/group does not exist')

    if service.owner_group_id == group.id:
        permission_names = service_type_dico[service.type].permission_names
    else:
        group_res_permission = db.query(models.GroupResourcePermission)\
            .filter(models.GroupResourcePermission.resource_id == service.resource_id)\
            .filter(models.GroupResourcePermission.group_id == group.id)
        permission_names = [permission.perm_name for permission in group_res_permission]

    return HTTPOk(
        body=json.dumps({'permission_names': permission_names}),
        content_type='application/json'
    )


@view_config(route_name='group_service_permissions', request_method='POST')
def create_group_service_permission(request):
    group_name = request.matchdict.get('group_name')
    service_name = request.matchdict.get('service_name')
    permission_name = request.POST.get('permission_name')

    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if service is None or group is None:
        db.rollback()
        raise HTTPNotFound(detail='this service/group does not exist')
    if permission_name not in service_type_dico[service.type].permission_names:
        db.rollback()
        raise HTTPBadRequest(detail='This permission is not allowed for that service')

    return create_group_resource_permission(permission_name, service.resource_id, group.id, db_session=db)

@view_config(route_name='group_service_permission', request_method='DELETE')
def delete_group_service_permission(request):
    group_name = request.matchdict.get('group_name')
    service_name = request.matchdict.get('service_name')
    permission_name = request.matchdict.get('permission_name')

    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if service is None or group is None:
        raise HTTPNotFound(detail='this service/group does not exist')
    if permission_name not in service_type_dico[service.type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that service')
    return delete_group_resource_permission(permission_name, service.resource_id, group.id, db_session=db)

def get_group_resources(request, resource_types):
    group_name = request.matchdict.get('group_name')
    db = request.db
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if group is None:
        raise HTTPBadRequest(detail='This group does not exist')
    resources = group.resources_with_possible_perms(resource_types=resource_types, db_session=db)

    resource_info_dic = {}
    for resource_tuple in resources:
        if resource_tuple.resource.resource_id in resource_info_dic.keys():
            resource_info_dic[resource_tuple.resource.resource_id]['permission_names'].append(resource_tuple.perm_name)
        else:
            resource_info = get_resource_info(resource_tuple.resource.resource_id, db_session=db)
            resource_info['permission_names'] = [resource_tuple.perm_name]
            resource_info_dic[resource_tuple.resource.resource_id] = resource_info

    return resource_info_dic


@view_config(route_name='group_resources', request_method='GET')
def get_group_resources_view(request):
    json_response = get_group_resources(request, resource_types=None)
    return HTTPOk(
        body=json.dumps({'resources': json_response}),
        content_type='application/json'
    )


@view_config(route_name='group_resources_type', request_method='GET')
def get_group_resources_types_view(request):
    json_response = get_group_resources(request, resource_types=[request.matchdict.get('resource_type')])
    return HTTPOk(
        body=json.dumps({'resources': json_response}),
        content_type='application/json'
    )

@view_config(route_name='group_resource_permissions', request_method='GET')
def get_group_resource_permissions(request):
    group_name = request.matchdict.get('group_name')
    resource_id = request.matchdict.get('resource_id')

    db = request.db
    resource = ResourceService.by_resource_id(resource_id=resource_id, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if resource is None or group is None:
        raise HTTPNotFound(detail='this resource/group does not exist')

    if resource.owner_group_id == group.id:
        permission_names = resource_type_dico[resource.type].permission_names
    else:
        group_res_permission = db.query(models.GroupResourcePermission)\
            .filter(models.GroupResourcePermission.resource_id == resource.resource_id)\
            .filter(models.GroupResourcePermission.group_id == group.id)
        permission_names = [permission.perm_name for permission in group_res_permission]

    return HTTPOk(
        body=json.dumps({'permission_names': permission_names}),
        content_type='application/json'
    )


def create_group_resource_permission(permission_name, resource_id, group_id, db_session):
    try:
        new_permission = models.GroupResourcePermission(resource_id=resource_id, group_id=group_id)
        new_permission.perm_name = permission_name
        db_session.add(new_permission)
        db_session.commit()
    except:
        db_session.rollback()
        raise HTTPConflict('This permission on that service already exists for that group')
    return HTTPOk()

@view_config(route_name='group_resource_permissions', request_method='POST')
def create_group_resource_permission_view(request):
    group_name = request.matchdict.get('group_name')
    resource_id = request.matchdict.get('resource_id')
    permission_name = request.POST.get('permission_name')

    db = request.db
    resource = ResourceService.by_resource_id(resource_id, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if resource is None or group is None:
        raise HTTPNotFound(detail='this service/group does not exist')
    if permission_name not in resource_type_dico[resource.resource_type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that service')

    return create_group_resource_permission(permission_name, resource.resource_id, group.id, db_session=db)



def delete_group_resource_permission(permission_name, resource_id, group_id, db_session):
    try:
        permission_to_delete = GroupResourcePermissionService.get(group_id, resource_id, permission_name, db_session=db_session)
        db_session.delete(permission_to_delete)
        db_session.commit()
    except:
        db_session.rollback()
        raise HTTPNotFound(detail="This permission on that service does not exist for that group")

    return HTTPOk()


@view_config(route_name='group_resource_permission', request_method='DELETE')
def delete_group_resource_permission_view(request):
    group_name = request.matchdict.get('group_name')
    resource_id = request.matchdict.get('resource_id')
    permission_name = request.matchdict.get('permission_name')

    db = request.db
    resource = ResourceService.by_resource_id(resource_id, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if resource is None or group is None:
        raise HTTPNotFound(detail='this service/group does not exist')
    if permission_name not in resource_type_dico[resource.resource_type].permission_names:
        raise HTTPBadRequest(detail='This permission is not allowed for that service')
    return delete_group_resource_permission(permission_name, resource.resource_id, group.id, db_session=db)



@view_config(route_name='group_service_resources', request_method='GET')
def get_group_service_resources(request):
    service_name = request.matchdict.get('service_name')
    group_name = request.matchdict.get('group_name')
    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    group = GroupService.by_group_name(group_name=group_name, db_session=db)
    if service is None or group is None:
        raise HTTPNotFound(detail='this service/group does not exist')

    tree_struct = resource_tree_service.from_parent_deeper(service.resource_id, db_session=db)
    children_ids = []
    for node in tree_struct:
        children_ids.append(node.Resource.resource_id)

    resources = group.resources_with_possible_perms(resource_ids=children_ids, db_session=db)
    resource_info_dic = {}
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





