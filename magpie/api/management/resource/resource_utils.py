from typing import TYPE_CHECKING

from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPOk
)
from pyramid.settings import asbool
from ziggurat_foundations.models.services.resource import ResourceService

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.resource.resource_formats import format_resource
from magpie.permissions import Permission
from magpie.register import sync_services_phoenix
from magpie.services import SERVICE_TYPE_DICT

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from pyramid.httpexceptions import HTTPException
    from sqlalchemy.orm.session import Session
    from magpie.typedefs import List, Str, Optional, Tuple, Type, ServiceOrResourceType, Union  # noqa: F401
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
    ax.verify_param(svc_res_perm, param_name="permission_name", param_compare=svc_res_permissions, is_in=True,
                    http_error=HTTPBadRequest,
                    content={"resource_type": str(svc_res_type), "resource_name": str(svc_res_name)},
                    msg_on_fail=s.UserResourcePermissions_POST_BadRequestResponseSchema.description)
    return svc_res_perm


def check_valid_service_resource(parent_resource, resource_type, db_session):
    """
    Checks if a new Resource can be contained under a parent Resource given the requested type and the corresponding
    Service under which the parent Resource is already assigned.

    :param parent_resource: Resource under which the new resource of `resource_type` must be placed
    :param resource_type: desired resource type
    :param db_session:
    :return: root Service if all checks were successful
    """
    parent_type = parent_resource.resource_type_name
    parent_msg_err = "Child resource not allowed for specified parent resource type '{}'".format(parent_type)
    ax.verify_param(models.RESOURCE_TYPE_DICT[parent_type].child_resource_allowed, is_equal=True,
                    param_compare=True, http_error=HTTPBadRequest, msg_on_fail=parent_msg_err)
    root_service = get_resource_root_service(parent_resource, db_session=db_session)
    ax.verify_param(root_service, not_none=True, http_error=HTTPInternalServerError,
                    msg_on_fail="Failed retrieving 'root_service' from db")
    ax.verify_param(root_service.resource_type, is_equal=True, http_error=HTTPInternalServerError,
                    param_name="resource_type", param_compare=models.Service.resource_type_name,
                    msg_on_fail="Invalid 'root_service' retrieved from db is not a service")
    ax.verify_param(SERVICE_TYPE_DICT[root_service.type].child_resource_allowed, is_equal=True,
                    param_compare=True, http_error=HTTPBadRequest,
                    msg_on_fail="Child resource not allowed for specified service type '{}'".format(root_service.type))
    ax.verify_param(resource_type, is_in=True, http_error=HTTPBadRequest,
                    param_name="resource_type", param_compare=SERVICE_TYPE_DICT[root_service.type].resource_type_names,
                    msg_on_fail="Invalid 'resource_type' specified for service type '{}'".format(root_service.type))
    return root_service


def crop_tree_with_permission(children, resource_id_list):
    for child_id, child_dict in list(children.items()):
        new_children = child_dict["children"]
        children_returned, resource_id_list = crop_tree_with_permission(new_children, resource_id_list)
        if child_id not in resource_id_list and not children_returned:
            children.pop(child_id)
        elif child_id in resource_id_list:
            resource_id_list.remove(child_id)
    return dict(children), list(resource_id_list)


def get_resource_path(resource_id, db_session):
    parent_resources = models.RESOURCE_TREE_SERVICE.path_upper(resource_id, db_session=db_session)
    parent_path = ""
    for parent_resource in parent_resources:
        parent_path = "/" + parent_resource.resource_name + parent_path
    return parent_path


def get_service_or_resource_types(service_or_resource):
    # type: (ServiceOrResourceType) -> Tuple[Type[ServiceInterface], Str]
    """
    Obtain the `service` or `resource` class and a corresponding ``"service"`` or ``"resource"`` type identifier.
    """
    if isinstance(service_or_resource, models.Service):
        svc_res_type_cls = SERVICE_TYPE_DICT[service_or_resource.type]
        svc_res_type_str = "service"
    elif isinstance(service_or_resource, models.Resource):
        svc_res_type_cls = models.RESOURCE_TYPE_DICT[service_or_resource.resource_type]
        svc_res_type_str = "resource"
    else:
        ax.raise_http(http_error=HTTPInternalServerError, detail="Invalid service/resource object",
                      content={"service_resource": repr(type(service_or_resource))})
    return svc_res_type_cls, svc_res_type_str   # noqa: W804


def get_resource_permissions(resource, db_session):
    # type: (models.Resource, Session) -> List[Permission]
    ax.verify_param(resource, not_none=True, http_error=HTTPBadRequest, param_name="resource",
                    msg_on_fail=s.UserResourcePermissions_GET_BadRequestResourceResponseSchema.description)
    # directly access the service resource
    if resource.root_service_id is None:
        service = resource  # type: models.Service  # noqa
        return SERVICE_TYPE_DICT[service.type].permissions

    # otherwise obtain root level service to infer sub-resource permissions
    service = ResourceService.by_resource_id(resource.root_service_id, db_session=db_session)
    ax.verify_param(service.resource_type, is_equal=True, http_error=HTTPBadRequest,
                    param_name="resource_type", param_compare=models.Service.resource_type_name,
                    msg_on_fail=s.UserResourcePermissions_GET_BadRequestRootServiceResponseSchema.description)
    service_class = SERVICE_TYPE_DICT[service.type]
    ax.verify_param(resource.resource_type_name, is_in=True, http_error=HTTPBadRequest,
                    param_name="resource_type", param_compare=service_class.resource_type_names,
                    msg_on_fail=s.UserResourcePermissions_GET_BadRequestResourceTypeResponseSchema.description)
    return service_class.get_resource_permissions(resource.resource_type_name)


def get_resource_root_service(resource, db_session):
    # type: (Union[models.Service, models.Resource], Session) -> Optional[models.Service]
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
    ax.verify_param(resource_name, param_name="resource_name", not_none=True, not_empty=True,
                    http_error=HTTPBadRequest,
                    msg_on_fail="Invalid 'resource_name' specified for child resource creation.")
    ax.verify_param(resource_type, param_name="resource_type", not_none=True, not_empty=True,
                    http_error=HTTPBadRequest,
                    msg_on_fail="Invalid 'resource_type' specified for child resource creation.")
    ax.verify_param(parent_id, param_name="parent_id", not_none=True, is_type=True, param_compare=int,
                    http_error=HTTPBadRequest, msg_on_fail="Invalid 'parent_id' specified for child resource creation.")
    parent_resource = ax.evaluate_call(lambda: ResourceService.by_resource_id(parent_id, db_session=db_session),
                                       fallback=lambda: db_session.rollback(), http_error=HTTPNotFound,
                                       msg_on_fail=s.Resources_POST_NotFoundResponseSchema.description,
                                       content={"parent_id": str(parent_id), "resource_name": str(resource_name),
                                                "resource_type": str(resource_type)})

    # verify for valid permissions from top-level service-specific corresponding resources permissions
    root_service = check_valid_service_resource(parent_resource, resource_type, db_session)
    new_resource = models.resource_factory(resource_type=resource_type,
                                           resource_name=resource_name,
                                           resource_display_name=resource_display_name or resource_name,
                                           root_service_id=root_service.resource_id,
                                           parent_id=parent_resource.resource_id)

    # Two resources with the same parent can't have the same name !
    tree_struct = models.RESOURCE_TREE_SERVICE.from_parent_deeper(parent_id, limit_depth=1, db_session=db_session)
    tree_struct_dict = models.RESOURCE_TREE_SERVICE.build_subtree_strut(tree_struct)
    direct_children = tree_struct_dict["children"]
    ax.verify_param(resource_name, param_name="resource_name", not_in=True, http_error=HTTPConflict,
                    msg_on_fail=s.Resources_POST_ConflictResponseSchema.description, with_param=False,
                    param_compare=[child_dict["node"].resource_name for child_dict in direct_children.values()])

    def add_resource_in_tree(new_res, db):
        db_session.add(new_res)
        total_children = models.RESOURCE_TREE_SERVICE.count_children(new_res.parent_id, db_session=db)
        models.RESOURCE_TREE_SERVICE.set_position(resource_id=new_res.resource_id,
                                                  to_position=total_children, db_session=db)

    ax.evaluate_call(lambda: add_resource_in_tree(new_resource, db_session),
                     fallback=lambda: db_session.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.Resources_POST_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPCreated, detail=s.Resources_POST_CreatedResponseSchema.description,
                         content={"resource": format_resource(new_resource, basic_info=True)})


def delete_resource(request):
    resource = ar.get_resource_matchdict_checked(request)
    service_push = asbool(ar.get_multiformat_body(request, "service_push"))
    res_content = {"resource": format_resource(resource, basic_info=True)}
    ax.evaluate_call(
        lambda: models.RESOURCE_TREE_SERVICE.delete_branch(resource_id=resource.resource_id, db_session=request.db),
        fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
        msg_on_fail="Delete resource branch from tree service failed.", content=res_content
    )

    def remove_service_magpie_and_phoenix(res, svc_push, db):
        if res.resource_type != "service":
            svc_push = False
        db.delete(res)
        if svc_push:
            sync_services_phoenix(db.query(models.Service))

    ax.evaluate_call(lambda: remove_service_magpie_and_phoenix(resource, service_push, request.db),
                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.Resource_DELETE_ForbiddenResponseSchema.description, content=res_content)
    return ax.valid_http(http_success=HTTPOk, detail=s.Resource_DELETE_OkResponseSchema.description)
