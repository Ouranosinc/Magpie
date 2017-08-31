from magpie import *
import models
from models import resource_tree_service
from models import resource_type_dico



def format_resource(resource, perms=[]):
    return {
        'resource_name': resource.resource_name,
        'resource_id': resource.resource_id,
        'parent_id': resource.parent_id,
        'resource_type': resource.resource_type,
        'children': {},
        'permission_names': perms
    }


def format_resource_tree(children, db_session, resources_perms_dico={}):
    formatted_resource_tree = {}
    for child_id, dico in children.items():
        resource = dico['node']
        new_children = dico['children']
        perms = []
        if resource.resource_id in resources_perms_dico.keys():
            perms = resources_perms_dico[resource.resource_id]

        formatted_resource_tree[child_id] = format_resource(resource, perms)
        formatted_resource_tree[child_id]['children'] = format_resource_tree(new_children,
                                                                             db_session=db_session,
                                                                             resources_perms_dico=resources_perms_dico)

    return formatted_resource_tree


def get_resource_children(resource, db_session):
    query = resource_tree_service.from_parent_deeper(resource.resource_id, db_session=db_session)
    tree_struct_dico = resource_tree_service.build_subtree_strut(query)
    return tree_struct_dico['children']


def format_resource_with_children(resource, db_session):
    resource_formatted = format_resource(resource)

    resource_formatted['children'] = format_resource_tree(
        get_resource_children(resource, db_session),
        db_session=db_session
    )
    return resource_formatted


def crop_tree_with_permission(children, resource_id_list):
    for child_id, child_dico in children.items():
        new_children = child_dico['children']
        children_returned, resource_id_list = crop_tree_with_permission(new_children, resource_id_list)
        is_in_resource_id_list = child_id in resource_id_list
        if not is_in_resource_id_list and not children_returned:
            a = children.keys()
            children.pop(child_id)
        elif is_in_resource_id_list:
            resource_id_list.remove(child_id)
    return children, resource_id_list


def get_resource_path(resource_id, db_session):
    parent_resources = resource_tree_service.path_upper(resource_id, db_session=db_session)
    parent_path = ''
    for parent_resource in parent_resources:
        parent_path = '/' + parent_resource.resource_name + parent_path

    return parent_path


@view_config(route_name='resource', request_method='GET')
def get_resource_view(request):
    resource_id = request.matchdict.get('resource_id')
    db = request.db
    try:
        resource = ResourceService.by_resource_id(resource_id, db_session=db)
    except Exception, e:
        raise HTTPBadRequest(detail=e.message)
    if not resource:
        db.rollback()
        raise HTTPNotFound(detail="This resource id does not exist")
    json_response = format_resource_with_children(resource, db_session=db)
    return HTTPOk(
        body=json.dumps({resource.resource_id: json_response}),
        content_type='application/json'
    )


def create_resource(resource_name, resource_type, parent_id, db_session):
    db = db_session
    try:
        parent_resource = ResourceService.by_resource_id(parent_id, db_session=db_session)
        if not parent_resource:
            raise HTTPBadRequest(detail='parent_id not valid')
    except:
        raise HTTPBadRequest(detail='parent_id not valid')
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
    resource_name = get_multiformat_post(request, 'resource_name')
    resource_type = get_multiformat_post(request, 'resource_type')
    parent_id = get_multiformat_post(request, 'parent_id')

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




@view_config(route_name='resource', request_method='PUT')
def update_resource(request):
    resource_id = request.matchdict.get('resource_id')
    new_name = get_multiformat_post(request, 'resource_name')
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

