from magpie import *
import models
from models import resource_tree_service




def get_resource_path(resource_id, db_session):
    parent_resources = resource_tree_service.path_upper(resource_id, db_session=db_session)
    parent_path = ''
    for parent_resource in parent_resources:
        parent_path = '/' + parent_resource.resource_name + parent_path

    return parent_path


def get_resource_info(resource_id, db_session):
    try:
        resource = ResourceService.by_resource_id(resource_id, db_session=db_session)
    except Exception, e:
        raise HTTPBadRequest(detail=e.message)
    if not resource:
        db_session.rollback()
        raise HTTPNotFound(detail="This resource id does not exist")
    parent_path = get_resource_path(resource.resource_id, db_session)

    #owner_user = UserService.by_id(resource.owner_user_id, db_session=db_session)
    #owner_group = GroupService.get(resource.owner_group_id, db_session=db_session)

    json_response = {
        'resource_name': resource.resource_name,
        'resource_type': resource.resource_type,
        #'owner_user_name': '' if not owner_user else owner_user.user_name,
        #'owner_group_name': '' if not owner_group else owner_group.group_name,
        'resource_path': parent_path
    }
    return json_response


@view_config(route_name='resource', request_method='GET')
def get_resource(request):
    resource_id = request.matchdict.get('resource_id')
    db = request.db
    json_response = get_resource_info(resource_id, db)

    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


def create_resource(resource_name, resource_type, parent_id, db_session):
    db = db_session
    try:
        new_resource = models.resource_factory(resource_type=resource_type,
                                               resource_name=resource_name,
                                               parent_id=parent_id)
    except Exception, e:
        db.rollback()
        raise HTTPBadRequest(detail=e.message)

    # Two resources with the same parent can't have the same name !
    tree_struct = resource_tree_service.from_parent_deeper(parent_id, limit_depth=1, db_session=db)
    tree_struct_dict = resource_tree_service.build_subtree_strut(tree_struct)
    direct_children = tree_struct_dict['children']
    if resource_name in [child_dico['node'].resource_name for child_dico in direct_children.values()]:
        db.rollback()
        raise HTTPConflict(detail='this resource name already exists at this tree level')
    try:
        db.add(new_resource)
        db.commit()
        total_children = resource_tree_service.count_children(new_resource.parent_id, db_session=db)
        resource_tree_service.set_position(resource_id=new_resource.resource_id,
                                           to_position=total_children,
                                           db_session=db)
    except Exception, e:
        db.rollback()
        raise HTTPBadRequest(detail=e.message)

    return HTTPCreated(body=json.dumps({'resource_id': new_resource.resource_id}),
                       content_type='application/json')


@view_config(route_name='resources', request_method='POST')
def create_resource_view(request):
    """
    Create a resource a place it somewhere
    :param request: 
    :return: 
    """
    resource_name = request.POST.get('resource_name')
    resource_type = request.POST.get('resource_type')
    parent_id = request.POST.get('parent_id')

    return create_resource(resource_name, resource_type, parent_id, request.db)



@view_config(route_name='service_resource', request_method='DELETE')
@view_config(route_name='resource', request_method='DELETE')
def delete_resources(request):
    try:
        resource_id = request.matchdict.get('resource_id')
        db = request.db
        resource = ResourceService.by_resource_id(resource_id=resource_id, db_session=db)
        resource_tree_service.delete_branch(resource_id=resource_id, db_session=db)
        db.delete(resource)
        db.commit()
    except:
        db.rollback()
        raise HTTPNotFound('Bad resource id')
    return HTTPOk()



@view_config(route_name='resources', request_method='GET')
def get_resources(request):
    resources = models.Resource.all(db_session=request.db)
    resource_info_dico = {}
    for resource in resources:
        resource_info_dico[resource.resource_id] = get_resource_info(resource.resource_id, request.db)

    json_response = {'resources': resource_info_dico}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='resource', request_method='PUT')
def update_resource(request):
    resource_id = request.matchdict.get('resource_id')
    new_name = request.POST.get('resource_name')
    db = request.db
    if new_name is None:
        raise HTTPBadRequest(detail='the new resource_name is missing')
    try:
        resource = ResourceService.by_resource_id(resource_id, db_session=db)
        resource.resource_name = new_name
        db.commit()
    except:
        db.rollback()
        raise HTTPNotFound('incorrect resource id')

    return HTTPOk()





@view_config(route_name='resource_permissions', request_method='GET')
def get_resource_permissions(request):
    resource_id = request.matchdict.get('resource_id')
    db = request.db
    resource = ResourceService.by_resource_id(resource_id, db_session=db)
    if resource:
        try:
            resource_permissions = models.resource_type_dico[resource.resource_type].permission_names
        except:
            db.rollback()
            raise HTTPNotFound(detail="This type of resource is not implemented yet")
    else:
        db.rollback()
        raise HTTPNotFound(detail="This resource does not exist")

    return HTTPOk(
        body=json.dumps({'permission_names': resource_permissions}),
        content_type='application/json'
    )

