from models import resource_factory
from resource_formats import *
from ziggurat_definitions import *
from api_except import *
from api_requests import get_service_or_resource_types


def check_valid_service_resource_permission(permission_name, service_resource):
    svc_res_obj, svc_res_type = get_service_or_resource_types(service_resource)
    verify_param(permission_name, paramCompare=svc_res_obj.permission_names,
                 isIn=True, httpError=HTTPBadRequest,
                 msgOnFail="Permission not allowed for that {} type".format(svc_res_type))


def get_specific_service_resource_permissions(service_resource):
    svc_res_obj, svc_res_type = get_service_or_resource_types(service_resource)
    return svc_res_obj.permission_names


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


def get_resource_permissions(resource, db_session):
    verify_param(resource, notNone=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `resource` specified for resource permission retrieval")
    if resource.root_service_id is None:  # directly access the service resource
        service = resource
    else:
        service = models.Service.by_resource_id(resource.root_service_id, db_session=db_session)
    verify_param(service.resource_type, isEqual=True, paramCompare=u'service', httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `root_service` specified for resource permission retrieval")
    service_obj = service_type_dict[service.type]
    verify_param(resource.resource_type, isIn=True, paramCompare=service_obj.resource_types,
                 httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `resource_type` for corresponding service resource permission retrieval")
    return service_obj.resource_types_permissions[resource.resource_type]


def get_resource_root_service(resource, db_session):
    """
    Recursively rewinds back through the top of the resource tree up to the top-level service-resource.

    :param resource: initial resource where to start searching upwards the tree
    :param db_session:
    :return: resource-tree root service as a resource object
    """
    if resource is not None:
        if resource.parent_id is None:
            return resource
        parent_resource = ResourceService.by_resource_id(resource.parent_id, db_session=db_session)
        return get_resource_root_service(parent_resource, db_session=db_session)
    return None


def create_resource(resource_name, resource_type, parent_id, db_session):
    verify_param(resource_name, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `resource_name` '" + str(resource_name) + "' specified for child resource creation")
    verify_param(resource_type, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `resource_type` '" + str(resource_type) + "' specified for child resource creation")
    verify_param(parent_id, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `parent_id` '" + str(parent_id) + "' specified for child resource creation")
    parent_resource = evaluate_call(lambda: ResourceService.by_resource_id(parent_id, db_session=db_session),
                                    fallback=lambda: db_session.rollback(), httpError=HTTPNotFound,
                                    msgOnFail="Could not find specified resource parent id",
                                    content={u'parent_id': str(parent_id), u'resource_name': str(resource_name),
                                             u'resource_type': str(resource_type)})

    # verify for valid permissions from top-level service-specific corresponding resources permissions
    root_service = get_resource_root_service(parent_resource, db_session=db_session)
    verify_param(root_service, notNone=True, httpError=HTTPInternalServerError,
                 msgOnFail="Failed retrieving `root_service` from db")
    verify_param(root_service.resource_type, isEqual=True, httpError=HTTPInternalServerError, paramCompare=u'service',
                 msgOnFail="Invalid `root_service` retrieved from db is not a service")
    verify_param(resource_type, isIn=True, httpError=HTTPNotAcceptable,
                 paramCompare=service_type_dict[root_service.type].resource_types,
                 msgOnFail="Invalid `resource_type` specified for service type `{}`".format(root_service.type))

    new_resource = resource_factory(resource_type=resource_type,
                                    resource_name=resource_name,
                                    root_service_id=root_service.resource_id,
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
                  httpError=HTTPForbidden, msgOnFail="Failed to insert new resource in service tree using parent id")
    return valid_http(httpSuccess=HTTPCreated, detail="Create resource successful",
                      content=format_resource(new_resource, basic_info=True))
