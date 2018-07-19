import models
from common import *
from models import resource_factory, resource_type_dict, resource_tree_service
from services import service_type_dict
from register import sync_services_phoenix
from magpie.definitions.pyramid_definitions import *
from magpie.definitions.ziggurat_definitions import *
from magpie.api.api_rest_schemas import *
from magpie.api.api_requests import *
from magpie.api.api_except import verify_param, evaluate_call, raise_http, valid_http
from magpie.api.management.resource.resource_formats import format_resource


def check_valid_service_resource_permission(permission_name, service_resource, db_session):
    """
    Checks if a permission is valid to be applied to a specific service or a resource under a specific service.
    :param permission_name: permission to apply
    :param service_resource: resource item corresponding to either a Service or a Resource
    :param db_session:
    :return:
    """
    svc_res_perms = get_resource_permissions(service_resource, db_session=db_session)
    svc_res_type = service_resource.resource_type
    svc_res_name = service_resource.resource_name
    verify_param(permission_name, paramName=u'permission_name', paramCompare=svc_res_perms, isIn=True,
                 httpError=HTTPBadRequest,
                 msgOnFail="Permission not allowed for {0} `{1}`".format(svc_res_type, svc_res_name))


def check_valid_service_resource(parent_resource, resource_type, db_session):
    """
    Checks if a new Resource can be contained under a parent Resource given the requested type and
    the corresponding Service under which the parent Resource is already assigned.

    :param parent_resource: Resource under which the new Resource of `resource_type` must be placed
    :param resource_type: desired Resource type
    :param db_session:
    :return: root Service if all checks were successful
    """
    parent_type = parent_resource.resource_type_name
    verify_param(resource_type_dict[parent_type].child_resource_allowed, isEqual=True,
                 paramCompare=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Child resource not allowed for specified parent resource type `{}`".format(parent_type))
    root_service = get_resource_root_service(parent_resource, db_session=db_session)
    verify_param(root_service, notNone=True, httpError=HTTPInternalServerError,
                 msgOnFail="Failed retrieving `root_service` from db")
    verify_param(root_service.resource_type, isEqual=True, httpError=HTTPInternalServerError,
                 paramName=u'resource_type', paramCompare=u'service',
                 msgOnFail="Invalid `root_service` retrieved from db is not a service")
    verify_param(service_type_dict[root_service.type].child_resource_allowed, isEqual=True,
                 paramCompare=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Child resource not allowed for specified service type `{}`".format(root_service.type))
    verify_param(resource_type, isIn=True, httpError=HTTPNotAcceptable,
                 paramName=u'resource_type', paramCompare=service_type_dict[root_service.type].resource_types,
                 msgOnFail="Invalid `resource_type` specified for service type `{}`".format(root_service.type))
    return root_service


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


def get_service_or_resource_types(service_resource):
    if isinstance(service_resource, models.Service):
        svc_res_type_obj = service_type_dict[service_resource.type]
        svc_res_type_str = u"service"
    elif isinstance(service_resource, models.Resource):
        svc_res_type_obj = resource_type_dict[service_resource.resource_type]
        svc_res_type_str = u"resource"
    else:
        raise_http(httpError=HTTPInternalServerError, detail="Invalid service/resource object",
                   content={u'service_resource': repr(type(service_resource))})
    return svc_res_type_obj, svc_res_type_str


def get_resource_permissions(resource, db_session):
    verify_param(resource, notNone=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `resource` specified for resource permission retrieval")
    # directly access the service resource
    if resource.root_service_id is None:
        service = resource
        return service_type_dict[service.type].permission_names

    # otherwise obtain root level service to infer sub-resource permissions
    service = models.Service.by_resource_id(resource.root_service_id, db_session=db_session)
    verify_param(service.resource_type, isEqual=True, httpError=HTTPNotAcceptable,
                 paramName=u'resource_type', paramCompare=u'service',
                 msgOnFail="Invalid `root_service` specified for resource permission retrieval")
    service_obj = service_type_dict[service.type]
    verify_param(resource.resource_type, isIn=True, httpError=HTTPNotAcceptable,
                 paramName=u'resource_type', paramCompare=service_obj.resource_types,
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
    verify_param(resource_name, paramName=u'resource_name', notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `resource_name` specified for child resource creation.")
    verify_param(resource_type, paramName=u'resource_type', notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `resource_type` specified for child resource creation.")
    verify_param(parent_id, paramName=u'parent_id', notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `parent_id` specified for child resource creation.")
    parent_resource = evaluate_call(lambda: ResourceService.by_resource_id(parent_id, db_session=db_session),
                                    fallback=lambda: db_session.rollback(), httpError=HTTPNotFound,
                                    msgOnFail=Resources_POST_NotFoundResponseSchema.description,
                                    content={u'parent_id': str(parent_id), u'resource_name': str(resource_name),
                                             u'resource_type': str(resource_type)})

    # verify for valid permissions from top-level service-specific corresponding resources permissions
    root_service = check_valid_service_resource(parent_resource, resource_type, db_session)
    new_resource = resource_factory(resource_type=resource_type,
                                    resource_name=resource_name,
                                    root_service_id=root_service.resource_id,
                                    parent_id=parent_resource.resource_id)

    # Two resources with the same parent can't have the same name !
    tree_struct = resource_tree_service.from_parent_deeper(parent_id, limit_depth=1, db_session=db_session)
    tree_struct_dict = resource_tree_service.build_subtree_strut(tree_struct)
    direct_children = tree_struct_dict[u'children']
    verify_param(resource_name, paramName=u'resource_name', notIn=True, httpError=HTTPConflict,
                 msgOnFail=Resources_POST_ConflictResponseSchema.description,
                 paramCompare=[child_dict[u'node'].resource_name for child_dict in direct_children.values()])

    def add_resource_in_tree(new_res, db):
        db_session.add(new_res)
        total_children = resource_tree_service.count_children(new_res.parent_id, db_session=db)
        resource_tree_service.set_position(resource_id=new_res.resource_id, to_position=total_children, db_session=db)

    evaluate_call(lambda: add_resource_in_tree(new_resource, db_session),
                  fallback=lambda: db_session.rollback(),
                  httpError=HTTPForbidden, msgOnFail=Resources_POST_ForbiddenResponseSchema.description)
    return valid_http(httpSuccess=HTTPCreated, detail=Resources_POST_OkResponseSchema.description,
                      content={u'resource': format_resource(new_resource, basic_info=True)})


def delete_resource(request):
    resource = get_resource_matchdict_checked(request)
    service_push = str2bool(get_multiformat_post(request, 'service_push'))
    res_content = {u'resource': format_resource(resource, basic_info=True)}
    evaluate_call(lambda: resource_tree_service.delete_branch(resource_id=resource.resource_id, db_session=request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Delete resource branch from tree service failed.", content=res_content)

    def remove_service_magpie_and_phoenix(res, svc_push, db):
        if res.resource_type != 'service':
            svc_push = False
        db.delete(res)
        if svc_push:
            sync_services_phoenix(db.query(models.Service))

    evaluate_call(lambda: remove_service_magpie_and_phoenix(resource, service_push, request.db),
                  fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail=Resource_DELETE_ForbiddenResponseSchema.description, content=res_content)
    return valid_http(httpSuccess=HTTPOk, detail=Resource_DELETE_OkResponseSchema.description)
