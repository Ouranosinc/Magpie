from models import resource_type_dict, resource_tree_service, resource_factory
from ziggurat_definitions import *
from api_except import *


def format_resource(resource, permissions=None, basic_info=False):
    def fmt_res(res, perms, info):
        if info:
            return {
                u'resource_name': str(res.resource_name),
                u'resource_type': str(res.resource_type),
                u'resource_id': res.resource_id
            }
        return {
            u'resource_name': str(res.resource_name),
            u'resource_type': str(res.resource_type),
            u'resource_id': res.resource_id,
            u'parent_id': res.parent_id,
            u'children': {},
            u'permission_names': list() if perms is None else perms
        }

    return evaluate_call(
        lambda: fmt_res(resource, permissions, basic_info),
        httpError=HTTPInternalServerError,
        msgOnFail="Failed to format resource",
        content={u'service': repr(resource), u'permissions': repr(permissions), u'basic_info': str(basic_info)}
    )


def format_resource_tree(children, db_session, resources_perms_dict=None):
    fmt_res_tree = {}
    for child_id, child_dict in children.items():
        resource = child_dict[u'node']
        new_children = child_dict[u'children']
        perms = []

        resources_perms_dict = dict() if resources_perms_dict is None else resources_perms_dict
        if resource.resource_id in resources_perms_dict.keys():
            perms = resources_perms_dict[resource.resource_id]

        fmt_res_tree[child_id] = format_resource(resource, perms)
        fmt_res_tree[child_id][u'children'] = format_resource_tree(new_children, db_session, resources_perms_dict)

    return fmt_res_tree


def get_resource_children(resource, db_session):
    query = resource_tree_service.from_parent_deeper(resource.resource_id, db_session=db_session)
    tree_struct_dict = resource_tree_service.build_subtree_strut(query)
    return tree_struct_dict[u'children']


def format_resource_with_children(resource, db_session):
    resource_formatted = format_resource(resource)

    resource_formatted[u'children'] = format_resource_tree(
        get_resource_children(resource, db_session),
        db_session=db_session
    )
    return resource_formatted


def crop_tree_with_permission(children, resource_id_list):
    for child_id, child_dict in children.items():
        new_children = child_dict[u'children']
        children_returned, resource_id_list = crop_tree_with_permission(new_children, resource_id_list)
        is_in_resource_id_list = child_id in resource_id_list
        if not is_in_resource_id_list and not children_returned:
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


def create_resource(resource_name, resource_type, parent_id, db_session):
    verify_param(resource_name, notNone=True, notEmpty=True,
                 msgOnFail="Invalid `resource_name` '" + str(resource_name) + "' specified for child resource creation")
    verify_param(resource_type, notNone=True, notEmpty=True,
                 msgOnFail="Invalid `resource_type` '" + str(resource_type) + "' specified for child resource creation")
    verify_param(parent_id, notNone=True, notEmpty=True,
                 msgOnFail="Invalid `parent_id` '" + str(parent_id) + "' specified for child resource creation")
    parent_resource = evaluate_call(lambda: ResourceService.by_resource_id(parent_id, db_session=db_session),
                                    fallback=lambda: db_session.rollback(), httpError=HTTPNotFound,
                                    msgOnFail="Could not find specified resource parent id",
                                    content={u'parent_id': str(parent_id), u'resource_name': str(resource_name),
                                             u'resource_type': str(resource_type)})
    new_resource = resource_factory(resource_type=resource_type,
                                    resource_name=resource_name,
                                    parent_id=parent_resource.resource_id)

    # Two resources with the same parent can't have the same name !
    tree_struct = resource_tree_service.from_parent_deeper(parent_id, limit_depth=1, db_session=db_session)
    tree_struct_dict = resource_tree_service.build_subtree_strut(tree_struct)
    direct_children = tree_struct_dict[u'children']
    verify_param(resource_name, notIn=True, httpError=HTTPConflict,
                 msgOnFail="Resource name already exists at requested tree level for creation",
                 paramCompare=[child_dict[u'node'].resource_name for child_dict in direct_children.values()])

    def add_resource_in_tree(new_res, db):
        db_session.add(new_res)
        total_children = resource_tree_service.count_children(new_res.parent_id, db_session=db)
        resource_tree_service.set_position(resource_id=new_res.resource_id, to_position=total_children, db_session=db)

    evaluate_call(lambda: add_resource_in_tree(new_resource, db_session),
                  fallback=lambda: db_session.rollback(),
                  httpError=HTTPBadRequest, msgOnFail="Failed to insert new resource in service tree using parent id")
    return valid_http(httpSuccess=HTTPCreated, detail="Create resource successful",
                      content=format_resource(new_resource, basic_info=True))
