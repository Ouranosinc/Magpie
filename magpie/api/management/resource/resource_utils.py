from magpie.api import requests as ar, exception as ax, schemas as s
from magpie.api.management.resource.resource_formats import format_resource
from magpie.definitions.ziggurat_definitions import ResourceService
from magpie.definitions.pyramid_definitions import (
    asbool,
    HTTPOk,
    HTTPCreated,
    HTTPBadRequest,
    HTTPForbidden,
    HTTPNotFound,
    HTTPNotAcceptable,
    HTTPConflict,
    HTTPInternalServerError,
)
from magpie import models
from magpie.permissions import Permission
from magpie.register import sync_services_phoenix
from magpie.services import SERVICE_TYPE_DICT
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.pyramid_definitions import HTTPException  # noqa: F401
    from magpie.definitions.sqlalchemy_definitions import Session  # noqa: F401
    from magpie.definitions.typedefs import List, Str, Optional, Tuple, Type, ServiceOrResourceType  # noqa: F401
    from magpie.services import ServiceInterface  # noqa: F401


def check_valid_service_or_resource_permission(permission_name, service_or_resource, db_session):
    # type: (Str, ServiceOrResourceType, Session) -> Optional[Permission]
    """
    Checks if a permission is valid to be applied to a specific `service` or a `resource` under a root service.

    :param permission_name: permission name to be validated
    :param service_or_resource: resource item corresponding to either a Service or a Resource
    :param db_session: db connection
    :return: valid Permission if allowed by the service/resource
    """
    svc_res_permissions = get_resource_permissions(service_or_resource, db_session=db_session)
    svc_res_type = service_or_resource.resource_type
    svc_res_name = service_or_resource.resource_name
    svc_res_perm = Permission.get(permission_name)
    ax.verify_param(svc_res_perm, paramName=u"permission_name", paramCompare=svc_res_permissions, isIn=True,
                    httpError=HTTPBadRequest,
                    content={u"resource_type": str(svc_res_type), u"resource_name": str(svc_res_name)},
                    msgOnFail=s.UserResourcePermissions_POST_BadRequestResponseSchema.description)
    return svc_res_perm


def check_valid_service_resource(parent_resource, resource_type, db_session):
    """
    Checks if a new Resource can be contained under a parent Resource given the requested type and
    the corresponding Service under which the parent Resource is already assigned.

    :param parent_resource: Resource under which the new resource of `resource_type` must be placed
    :param resource_type: desired resource type
    :param db_session:
    :return: root Service if all checks were successful
    """
    parent_type = parent_resource.resource_type_name
    ax.verify_param(models.RESOURCE_TYPE_DICT[parent_type].child_resource_allowed, isEqual=True,
                    paramCompare=True, httpError=HTTPNotAcceptable,
                    msgOnFail="Child resource not allowed for specified parent resource type '{}'".format(parent_type))
    root_service = get_resource_root_service(parent_resource, db_session=db_session)
    ax.verify_param(root_service, notNone=True, httpError=HTTPInternalServerError,
                    msgOnFail="Failed retrieving 'root_service' from db")
    ax.verify_param(root_service.resource_type, isEqual=True, httpError=HTTPInternalServerError,
                    paramName=u"resource_type", paramCompare=models.Service.resource_type_name,
                    msgOnFail="Invalid 'root_service' retrieved from db is not a service")
    ax.verify_param(SERVICE_TYPE_DICT[root_service.type].child_resource_allowed, isEqual=True,
                    paramCompare=True, httpError=HTTPNotAcceptable,
                    msgOnFail="Child resource not allowed for specified service type '{}'".format(root_service.type))
    ax.verify_param(resource_type, isIn=True, httpError=HTTPNotAcceptable,
                    paramName=u"resource_type", paramCompare=SERVICE_TYPE_DICT[root_service.type].resource_type_names,
                    msgOnFail="Invalid 'resource_type' specified for service type '{}'".format(root_service.type))
    return root_service


def crop_tree_with_permission(children, resource_id_list):
    for child_id, child_dict in list(children.items()):
        new_children = child_dict[u"children"]
        children_returned, resource_id_list = crop_tree_with_permission(new_children, resource_id_list)
        if child_id not in resource_id_list and not children_returned:
            children.pop(child_id)
        elif child_id in resource_id_list:
            resource_id_list.remove(child_id)
    return dict(children), list(resource_id_list)


def get_resource_path(resource_id, db_session):
    parent_resources = models.resource_tree_service.path_upper(resource_id, db_session=db_session)
    parent_path = ""
    for parent_resource in parent_resources:
        parent_path = "/" + parent_resource.resource_name + parent_path
    return parent_path


def get_service_or_resource_types(service_or_resource):
    # type: (ServiceOrResourceType) -> Tuple[Type[ServiceInterface], Str]
    """Obtain the `service` or `resource` class and a corresponding ``"service"`` or ``"resource"`` type identifier."""
    if isinstance(service_or_resource, models.Service):
        svc_res_type_cls = SERVICE_TYPE_DICT[service_or_resource.type]
        svc_res_type_str = u"service"
    elif isinstance(service_or_resource, models.Resource):
        svc_res_type_cls = models.RESOURCE_TYPE_DICT[service_or_resource.resource_type]
        svc_res_type_str = u"resource"
    else:
        ax.raise_http(httpError=HTTPInternalServerError, detail="Invalid service/resource object",
                      content={u"service_resource": repr(type(service_or_resource))})
    # noinspection PyUnboundLocalVariable
    return svc_res_type_cls, svc_res_type_str


def get_resource_permissions(resource, db_session):
    # type: (models.Resource, Session) -> List[Permission]
    ax.verify_param(resource, notNone=True, httpError=HTTPNotAcceptable, paramName=u"resource",
                    msgOnFail=s.UserResourcePermissions_GET_NotAcceptableResourceResponseSchema.description)
    # directly access the service resource
    if resource.root_service_id is None:
        service = resource
        return SERVICE_TYPE_DICT[service.type].permissions

    # otherwise obtain root level service to infer sub-resource permissions
    service = ResourceService.by_resource_id(resource.root_service_id, db_session=db_session)
    ax.verify_param(service.resource_type, isEqual=True, httpError=HTTPNotAcceptable,
                    paramName=u"resource_type", paramCompare=models.Service.resource_type_name,
                    msgOnFail=s.UserResourcePermissions_GET_NotAcceptableRootServiceResponseSchema.description)
    service_class = SERVICE_TYPE_DICT[service.type]
    ax.verify_param(resource.resource_type_name, isIn=True, httpError=HTTPNotAcceptable,
                    paramName=u"resource_type", paramCompare=service_class.resource_type_names,
                    msgOnFail=s.UserResourcePermissions_GET_NotAcceptableResourceTypeResponseSchema.description)
    return service_class.get_resource_permissions(resource.resource_type_name)


def get_resource_root_service(resource, db_session):
    # type: (models.Resource, Session) -> Optional[models.Resource]
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


def create_resource(resource_name, resource_display_name, resource_type, parent_id, db_session):
    # type: (Str, Optional[Str], Str, int, Session) -> HTTPException
    ax.verify_param(resource_name, paramName=u"resource_name", notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                    msgOnFail="Invalid 'resource_name' specified for child resource creation.")
    ax.verify_param(resource_type, paramName=u"resource_type", notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                    msgOnFail="Invalid 'resource_type' specified for child resource creation.")
    ax.verify_param(parent_id, paramName=u"parent_id", notNone=True, notEmpty=True, paramCompare=int, ofType=True,
                    httpError=HTTPBadRequest, msgOnFail="Invalid 'parent_id' specified for child resource creation.")
    parent_resource = ax.evaluate_call(lambda: ResourceService.by_resource_id(parent_id, db_session=db_session),
                                       fallback=lambda: db_session.rollback(), httpError=HTTPNotFound,
                                       msgOnFail=s.Resources_POST_NotFoundResponseSchema.description,
                                       content={u"parent_id": str(parent_id), u"resource_name": str(resource_name),
                                                u"resource_type": str(resource_type)})

    # verify for valid permissions from top-level service-specific corresponding resources permissions
    root_service = check_valid_service_resource(parent_resource, resource_type, db_session)
    new_resource = models.resource_factory(resource_type=resource_type,
                                           resource_name=resource_name,
                                           resource_display_name=resource_display_name or resource_name,
                                           root_service_id=root_service.resource_id,
                                           parent_id=parent_resource.resource_id)

    # Two resources with the same parent can't have the same name !
    tree_struct = models.resource_tree_service.from_parent_deeper(parent_id, limit_depth=1, db_session=db_session)
    tree_struct_dict = models.resource_tree_service.build_subtree_strut(tree_struct)
    direct_children = tree_struct_dict[u"children"]
    ax.verify_param(resource_name, paramName=u"resource_name", notIn=True, httpError=HTTPConflict,
                    msgOnFail=s.Resources_POST_ConflictResponseSchema.description,
                    paramCompare=[child_dict[u"node"].resource_name for child_dict in direct_children.values()])

    def add_resource_in_tree(new_res, db):
        db_session.add(new_res)
        total_children = models.resource_tree_service.count_children(new_res.parent_id, db_session=db)
        models.resource_tree_service.set_position(resource_id=new_res.resource_id,
                                                  to_position=total_children, db_session=db)

    ax.evaluate_call(lambda: add_resource_in_tree(new_resource, db_session),
                     fallback=lambda: db_session.rollback(),
                     httpError=HTTPForbidden, msgOnFail=s.Resources_POST_ForbiddenResponseSchema.description)
    return ax.valid_http(httpSuccess=HTTPCreated, detail=s.Resources_POST_CreatedResponseSchema.description,
                         content={u"resource": format_resource(new_resource, basic_info=True)})


def delete_resource(request):
    resource = ar.get_resource_matchdict_checked(request)
    service_push = asbool(ar.get_multiformat_post(request, "service_push"))
    res_content = {u"resource": format_resource(resource, basic_info=True)}
    ax.evaluate_call(
        lambda: models.resource_tree_service.delete_branch(resource_id=resource.resource_id, db_session=request.db),
        fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
        msgOnFail="Delete resource branch from tree service failed.", content=res_content
    )

    def remove_service_magpie_and_phoenix(res, svc_push, db):
        if res.resource_type != "service":
            svc_push = False
        db.delete(res)
        if svc_push:
            sync_services_phoenix(db.query(models.Service))

    ax.evaluate_call(lambda: remove_service_magpie_and_phoenix(resource, service_push, request.db),
                     fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                     msgOnFail=s.Resource_DELETE_ForbiddenResponseSchema.description, content=res_content)
    return ax.valid_http(httpSuccess=HTTPOk, detail=s.Resource_DELETE_OkResponseSchema.description)
