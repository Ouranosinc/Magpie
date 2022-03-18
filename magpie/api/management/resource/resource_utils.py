from typing import TYPE_CHECKING

from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPOk,
    HTTPUnprocessableEntity
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
from magpie.services import SERVICE_TYPE_DICT, service_factory

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import List, Optional, Tuple, Type, Union

    from pyramid.httpexceptions import HTTPException
    from pyramid.request import Request
    from sqlalchemy.orm.session import Session
    from ziggurat_foundations.models.services.resource_tree import ResourceTreeService

    from magpie.services import ServiceInterface
    from magpie.typedefs import NestedResourceNodes, ServiceOrResourceType, Str


def check_valid_service_or_resource_permission(permission_name, service_or_resource, db_session):
    # type: (Union[Str, Permission], ServiceOrResourceType, Session) -> Optional[Permission]
    """
    Checks if a permission is valid to be applied to a specific `service` or a `resource` under a root service.

    :param permission_name: permission name to be validated
    :param service_or_resource: resource item corresponding to either a Service or a Resource
    :param db_session: db connection
    :return: valid Permission if allowed by the service/resource
    :raises HTTPBadRequest: if the permission is not valid for the targeted service/resource
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
    # type: (ServiceOrResourceType, Str, Session) -> models.Service
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
    ax.verify_param(models.RESOURCE_TYPE_DICT[parent_type].child_resource_allowed, is_true=True,
                    http_error=HTTPForbidden, msg_on_fail=parent_msg_err)
    root_service = get_resource_root_service(parent_resource, db_session=db_session)
    ax.verify_param(root_service, not_none=True, http_error=HTTPInternalServerError,
                    msg_on_fail="Failed retrieving 'root_service' from db")
    ax.verify_param(root_service.resource_type, is_equal=True, http_error=HTTPInternalServerError,
                    param_name="resource_type", param_compare=models.Service.resource_type_name,
                    msg_on_fail="Invalid 'root_service' retrieved from db is not a service")
    root_svc_cls = SERVICE_TYPE_DICT[root_service.type]
    ax.verify_param(root_svc_cls.child_resource_allowed, is_true=True, http_error=HTTPForbidden,
                    msg_on_fail="Child resource not allowed for specified service type '{}'".format(root_service.type))
    ax.verify_param(resource_type, is_in=True, http_error=HTTPForbidden,
                    param_name="resource_type", param_compare=root_svc_cls.resource_type_names,
                    msg_on_fail="Invalid 'resource_type' specified for service type '{}'".format(root_service.type))
    ax.verify_param(
        root_svc_cls.validate_nested_resource_type(parent_resource, resource_type), is_true=True,
        param_content={
            "resource_structure_allowed": root_svc_cls.child_structure_allowed,
            "resource_types_allowed": [
                res.resource_type for res in root_svc_cls.nested_resource_allowed(parent_resource)
            ]
        },
        http_error=HTTPUnprocessableEntity,
        msg_on_fail=(
            "Invalid 'resource_type' specified for service type '{}' is not allowed at this position "
            "under '{}' resource.".format(root_service.type, parent_type)
        )
    )
    return root_service


def check_unique_child_resource_name(resource_name, parent_id, error_message, db_session):
    # type: (Str, int, Str, Session) -> None
    """
    Verify that resource will be unique amongst other resources at the same target position.

    Verifies that the provided :paramref:`resource_name` does not already exist amongst other children resources at the
    level immediately under the parent, for the specified parent resource.

    :returns: nothing if no conflict detected
    :raises HTTPConflict: if the :paramref:`resource_name` conflict with another existing resource
    """
    tree_struct = models.RESOURCE_TREE_SERVICE.from_parent_deeper(parent_id, limit_depth=1, db_session=db_session)
    tree_struct_dict = models.RESOURCE_TREE_SERVICE.build_subtree_strut(tree_struct)
    direct_children = tree_struct_dict["children"]
    ax.verify_param(resource_name, param_name="resource_name", not_in=True,
                    param_compare=[child_dict["node"].resource_name for child_dict in direct_children.values()],
                    http_error=HTTPConflict, msg_on_fail=error_message)


def crop_tree_with_permission(children, resource_id_list):
    # type: (NestedResourceNodes, List[int]) -> Tuple[NestedResourceNodes, List[int]]
    """
    Recursively prunes all children resources from the tree hierarchy *except* listed ones matched by ID.

    Input :paramref:`children` is expected to be a dictionary of resource nodes and children resources with their ID
    as keys::

        {
            <res-id>: {
                "node": <res>,
                "children": {
                    <res-id>: {
                        "node": <res>,
                        "children": { <...> }
                    },
                    <...>
            },
            <...>
        }

    :param children: full hierarchy of children resource nodes.
    :param resource_id_list: resource IDs of nodes to preserve.
    :return: pruned hierarchy of resource nodes.
    """
    for child_id, child_dict in list(children.items()):
        new_children = child_dict["children"]
        children_returned, resource_id_list = crop_tree_with_permission(new_children, resource_id_list)
        if child_id not in resource_id_list and not children_returned:
            children.pop(child_id)
        elif child_id in resource_id_list:
            resource_id_list.remove(child_id)
    return dict(children), list(resource_id_list)


def get_resource_path(resource_id, db_session):
    # type: (int, Session) -> Str
    """
    Obtains the full path representation of the specified resource ID from the root service it resides under using all
    respective names of the intermediate resources.

    For example, the following hierarchy::

        <service-1> (id: 1)
            <resource-1> (id: 2)
                <resource-2> (id: 3)

    Will return the following path: ``/service-1/resource-1/resource-2``.

    This is the same representation of the ``resource`` field within startup permissions configuration file.
    """
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
    svc_res_type_cls = svc_res_type_str = None
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


def get_resource_parents(resource, db_session, tree_service_builder=None):
    # type: (ServiceOrResourceType, Session, Optional[ResourceTreeService]) -> List[ServiceOrResourceType]
    """
    Obtains the parent resource nodes of the input service or resource.

    :param resource: Initial resource where to start building the list from.
    :param db_session: Database connection to retrieve resources.
    :param tree_service_builder: Utility that build the tree (default: :py:data:`models.RESOURCE_TREE_SERVICE`).
    :returns: List of resources starting at input resource going all the way down to the root service.
    """
    if tree_service_builder is None:
        tree_service_builder = models.RESOURCE_TREE_SERVICE
    parents = tree_service_builder.path_upper(resource.resource_id, db_session=db_session)
    return list(parents)


def get_resource_children(resource, db_session, tree_service_builder=None):
    # type: (ServiceOrResourceType, Session, Optional[ResourceTreeService]) -> NestedResourceNodes
    """
    Obtains the children resource node structure of the input service or resource.

    :param resource: Initial resource where to start building the tree from.
    :param db_session: Database connection to retrieve resources.
    :param tree_service_builder: Utility that build the tree (default: :py:data:`models.RESOURCE_TREE_SERVICE`).
    :returns: ``{node: Resource, children: {node_id: <recursive>}}``
    """
    if tree_service_builder is None:
        tree_service_builder = models.RESOURCE_TREE_SERVICE
    query = tree_service_builder.from_parent_deeper(resource.resource_id, db_session=db_session)
    tree_struct_dict = tree_service_builder.build_subtree_strut(query)
    return tree_struct_dict["children"]


def get_resource_permissions(resource, db_session):
    # type: (ServiceOrResourceType, Session) -> List[Permission]
    """
    Obtains the applicable permissions on the service or resource, accordingly to what was provided.

    When parsing a resource, rewinds the hierarchy up to the top-most service in order to find the context under which
    the resource resides, and therefore which permissions this resource is allowed to have under that service.
    """
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
    # type: (ServiceOrResourceType, Session) -> Optional[models.Service]
    """
    Retrieves the service-specialized resource corresponding to the top-level resource in the tree hierarchy.

    .. seealso::
        - :func:`get_resource_root_service_by_id` for same operation but using the resource ID
        - :func:`get_resource_root_service_impl` to retrieve the explicit service's implementation
    """
    if resource is not None:
        if resource.resource_type == models.Service.resource_type_name:
            return resource
        return ResourceService.by_resource_id(resource.root_service_id, db_session=db_session)
    return None


def get_resource_root_service_by_id(resource_id, db_session):
    # type: (ServiceOrResourceType, Session) -> Optional[models.Service]
    """
    Retrieves the service-specialized resource corresponding to the top-level resource in the tree hierarchy.

    .. seealso::
        - :func:`get_resource_root_service` for same operation but directly using the resource
    """
    resource = ResourceService.by_resource_id(resource_id, db_session=db_session)
    if resource is None:
        return None
    return get_resource_root_service(resource, db_session=db_session)


def get_resource_root_service_impl(resource, request):
    # type: (ServiceOrResourceType, Request) -> ServiceInterface
    """
    Obtain the root service implementation.

    Retrieves the root-resource from the provided resource within a tree hierarchy and generates the
    corresponding top-level service's implementation from the :func:`service_factory`.

    .. seealso::
        :func:`get_resource_root_service` to retrieve only the service flavored resource model
    """
    service = get_resource_root_service(resource, db_session=request.db)
    return service_factory(service, request)


def create_resource(resource_name, resource_display_name, resource_type, parent_id, db_session):
    # type: (Str, Optional[Str], Str, int, Session) -> HTTPException
    ax.verify_param(resource_name, param_name="resource_name", not_none=True, not_empty=True,
                    matches=True, param_compare=ax.SCOPE_REGEX,
                    http_error=HTTPUnprocessableEntity,
                    msg_on_fail="Invalid 'resource_name' specified for child resource creation.")
    ax.verify_param(resource_type, param_name="resource_type", not_none=True, not_empty=True,
                    http_error=HTTPUnprocessableEntity,
                    msg_on_fail="Invalid 'resource_type' specified for child resource creation.")
    ax.verify_param(parent_id, param_name="parent_id", not_none=True, is_type=True, param_compare=int,
                    http_error=HTTPUnprocessableEntity,
                    msg_on_fail="Invalid 'parent_id' specified for child resource creation.")
    parent_resource = ax.evaluate_call(lambda: ResourceService.by_resource_id(parent_id, db_session=db_session),
                                       fallback=lambda: db_session.rollback(), http_error=HTTPNotFound,
                                       msg_on_fail=s.Resources_POST_NotFoundResponseSchema.description,
                                       content={"parent_id": parent_id, "resource_name": str(resource_name),
                                                "resource_type": str(resource_type)})

    # verify for valid permissions from top-level service-specific corresponding resources permissions
    root_service = check_valid_service_resource(parent_resource, resource_type, db_session)
    new_resource = models.resource_factory(resource_type=resource_type,
                                           resource_name=resource_name,
                                           resource_display_name=resource_display_name or resource_name,
                                           root_service_id=root_service.resource_id,
                                           parent_id=parent_resource.resource_id)

    # two resources with the same parent can't have the same name
    err_msg = s.Resources_POST_ConflictResponseSchema.description
    check_unique_child_resource_name(resource_name, parent_id, err_msg, db_session=db_session)

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
    service_push = asbool(ar.get_multiformat_body(request, "service_push", default=False))
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
