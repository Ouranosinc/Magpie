from typing import TYPE_CHECKING

from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPOk
)
from pyramid.settings import asbool
from pyramid.view import view_config
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.user import UserService

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.resource import resource_formats as rf
from magpie.api.management.resource import resource_utils as ru
from magpie.api.management.service import service_formats as sf
from magpie.api.management.service.service_utils import get_services_by_type
from magpie.api.management.user import user_utils as uu
from magpie.permissions import PermissionType, format_permissions
from magpie.register import magpie_register_permissions_from_config, sync_services_phoenix
from magpie.services import SERVICE_TYPE_DICT, get_resource_child_allowed

if TYPE_CHECKING:
    from typing import List

    from magpie.typedefs import JSON, AnyRequestType, AnyResponseType, NestingKeyType


@s.ResourcesAPI.get(tags=[s.ResourcesTag], response_schemas=s.Resources_GET_responses)
@view_config(route_name=s.ResourcesAPI.name, request_method="GET")
def get_resources_view(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    List all registered resources.
    """
    res_json = {}
    for svc_type in SERVICE_TYPE_DICT:
        services = get_services_by_type(svc_type, db_session=request.db)
        res_json[svc_type] = {}
        for svc in services:
            res_json[svc_type][svc.resource_name] = sf.format_service_resources(
                svc, request.db, show_all_children=True, show_private_url=False)
    res_json = {"resources": res_json}
    return ax.valid_http(http_success=HTTPOk, detail=s.Resources_GET_OkResponseSchema.description, content=res_json)


def get_resource_handler(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    Obtains the resource specified by the request with all applicable parameter validation and handling.
    """
    resource = ar.get_resource_matchdict_checked(request)

    # additional check only for endpoint based under service, resource-based endpoint accesses the resource directly
    if "service_name" in request.matchdict:
        # if the requested resource ID is the service itself, 'root_service_id=None', must check 'resource_id' also
        service = ar.get_service_matchdict_checked(request)
        ax.verify_param(
            service.resource_id, [resource.root_service_id, resource.resource_id],
            is_in=True, param_name="service_name",
            http_error=HTTPNotFound,
            content={
                "service": sf.format_service(service, basic_info=True),
                "resource": rf.format_resource(resource, basic_info=True),
            },
            msg_on_fail="Requested resource is not located under the specified service.",
        )

    parents = asbool(ar.get_query_param(request, ["parents", "parent"], False))
    flatten = False
    if parents:
        flatten = asbool(ar.get_query_param(request, ["flatten", "flattened", "list"], False))
        invert = asbool(ar.get_query_param(request, ["invert", "inverted"], False))
        # listing as "requested-ressource -> ... -> root-service"
        res_parents = ax.evaluate_call(lambda: ru.get_resource_parents(resource, db_session=request.db),
                                       fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                                       msg_on_fail=s.Resource_GET_InternalServerErrorResponseSchema.description,
                                       content={"resource": rf.format_resource(resource, basic_info=False)})

        if invert:
            # listing of parents, but inverted to obtain "root-service -> ... -> requested-ressource"
            # therefore, nested items are back to being children once again
            nesting = "children"  # type: NestingKeyType
            res_parents = list(reversed(res_parents))
        else:
            nesting = "parent"
        if flatten:
            res_json = ax.evaluate_call(
                lambda: rf.format_resources_listed(res_parents, db_session=request.db),
                fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                msg_on_fail=s.Resource_GET_InternalServerErrorResponseSchema.description,
                content={"resource": rf.format_resource(resource, basic_info=False)})
        else:
            # When using nested objects, top-most is handled differently because of normal children hierarchy
            # in order to report the service details. When using listing, they are all processed the same way.
            top_res = res_parents[0]
            sub_res = res_parents[1:]
            res_nested = {}  # nest resources bottom-up with expected structure for formatter
            for parent_res in reversed(sub_res):
                res_nested = {parent_res.resource_id: {"node": parent_res, "children": res_nested}}
            res_json = ax.evaluate_call(
                lambda: rf.format_resources_nested(top_res, res_nested, nesting_key=nesting, db_session=request.db),
                fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                msg_on_fail=s.Resource_GET_InternalServerErrorResponseSchema.description,
                content={"resource": rf.format_resource(resource, basic_info=False)})
    else:
        res_children = ax.evaluate_call(
            lambda: ru.get_resource_children(resource, request.db),
            fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
            msg_on_fail=s.Resource_GET_InternalServerErrorResponseSchema.description,
            content={"resource": rf.format_resource(resource, basic_info=False)})
        res_json = ax.evaluate_call(
            lambda: rf.format_resources_nested(resource, res_children, nesting_key="children", db_session=request.db),
            fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
            msg_on_fail=s.Resource_GET_InternalServerErrorResponseSchema.description,
            content={"resource": rf.format_resource(resource, basic_info=False)})
    res_key = "resources" if flatten else "resource"
    return ax.valid_http(http_success=HTTPOk, content={res_key: res_json},
                         detail=s.Resource_GET_OkResponseSchema.description)


@s.ResourceAPI.get(schema=s.Resource_GET_RequestSchema, tags=[s.ResourcesTag],
                   response_schemas=s.Resource_GET_responses)
@view_config(route_name=s.ResourceAPI.name, request_method="GET")
def get_resource_view(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    Get resource information.
    """
    return get_resource_handler(request)


@s.ResourcesAPI.post(schema=s.Resources_POST_RequestSchema, tags=[s.ResourcesTag],
                     response_schemas=s.Resources_POST_responses)
@view_config(route_name=s.ResourcesAPI.name, request_method="POST")
def create_resource_view(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    Register a new resource.
    """
    resource_name = ar.get_multiformat_body(request, "resource_name")
    resource_display_name = ar.get_multiformat_body(request, "resource_display_name", default=resource_name)
    resource_type = ar.get_value_multiformat_body_checked(request, "resource_type")
    parent_id = ar.get_value_multiformat_body_checked(request, "parent_id", check_type=int)
    return ru.create_resource(resource_name, resource_display_name, resource_type, parent_id, request.db)


@s.ResourceAPI.delete(schema=s.Resource_DELETE_RequestSchema, tags=[s.ResourcesTag],
                      response_schemas=s.Resources_DELETE_responses)
@view_config(route_name=s.ResourceAPI.name, request_method="DELETE")
def delete_resource_view(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    Unregister a resource.
    """
    return ru.delete_resource(request)


@s.ResourceAPI.patch(schema=s.Resource_PATCH_RequestSchema, tags=[s.ResourcesTag],
                     response_schemas=s.Resource_PATCH_responses)
@view_config(route_name=s.ResourceAPI.name, request_method="PATCH")
def update_resource(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    Update a resource information.
    """
    resource = ar.get_resource_matchdict_checked(request, "resource_id")
    service_push = asbool(ar.get_multiformat_body(request, "service_push", default=False))
    res_old_name = resource.resource_name
    res_new_name = ar.get_value_multiformat_body_checked(request, "resource_name")
    ax.verify_param(res_new_name, not_equal=True, param_compare=res_old_name, param_name="resource_name",
                    http_error=HTTPBadRequest, msg_on_fail=s.Resource_PATCH_BadRequestResponseSchema.description)
    db_session = request.db

    # check for conflicting name, either with services or children resources
    err_msg = s.Resource_PATCH_ConflictResponseSchema.description
    is_res_svc = resource.resource_type == models.Service.resource_type_name
    if is_res_svc:
        all_services = db_session.query(models.Service)
        all_svc_names = [svc.resource_name for svc in all_services]
        ax.verify_param(res_new_name, not_in=True, param_compare=all_svc_names, with_param=False,
                        http_error=HTTPConflict, content={"resource_name": str(res_new_name)}, msg_on_fail=err_msg)
    else:
        ru.check_unique_child_resource_name(res_new_name, resource.parent_id, err_msg, db_session=db_session)

    def rename_service_magpie_and_phoenix():
        resource.resource_name = res_new_name
        if is_res_svc and service_push:
            sync_services_phoenix(all_services)

    ax.evaluate_call(lambda: rename_service_magpie_and_phoenix(),
                     fallback=lambda: db_session.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.Resource_PATCH_ForbiddenResponseSchema.description,
                     content={"resource_id": resource.resource_id, "resource_name": resource.resource_name,
                              "old_resource_name": res_old_name, "new_resource_name": res_new_name})
    return ax.valid_http(http_success=HTTPOk, detail=s.Resource_PATCH_OkResponseSchema.description,
                         content={"resource_id": resource.resource_id, "resource_name": resource.resource_name,
                                  "old_resource_name": res_old_name, "new_resource_name": res_new_name})


@s.ResourcePermissionsAPI.get(schema=s.ResourcePermissions_GET_RequestSchema, tags=[s.ResourcesTag],
                              response_schemas=s.ResourcePermissions_GET_responses)
@view_config(route_name=s.ResourcePermissionsAPI.name, request_method="GET")
def get_resource_permissions_view(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    List all applicable permissions for a resource.
    """
    resource = ar.get_resource_matchdict_checked(request, "resource_id")
    res_perm = ax.evaluate_call(lambda: ru.get_resource_permissions(resource, db_session=request.db),
                                fallback=lambda: request.db.rollback(), http_error=HTTPBadRequest,
                                msg_on_fail=s.ResourcePermissions_GET_BadRequestResponseSchema.description,
                                content={"resource": rf.format_resource(resource, basic_info=True)})
    return ax.valid_http(http_success=HTTPOk, detail=s.ResourcePermissions_GET_OkResponseSchema.description,
                         content=format_permissions(res_perm, PermissionType.ALLOWED))


@s.ResourceTypesAPI.get(schema=s.ResourceTypes_GET_RequestSchema, tags=[s.ResourcesTag],
                        response_schemas=s.ResourceTypes_GET_responses)
@view_config(route_name=s.ResourceTypesAPI.name, request_method="GET")
def get_resource_types_view(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    List all applicable children resource types under another resource within a service hierarchy.
    """
    resource = ar.get_resource_matchdict_checked(request, "resource_id")

    def get_res_types(res):
        svc_root = ru.get_resource_root_service(res, db_session=request.db)
        svc_impl = SERVICE_TYPE_DICT[svc_root.type]
        return svc_impl.nested_resource_allowed(res), svc_root

    res_types, svc = ax.evaluate_call(lambda: get_res_types(resource),
                                      fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                                      msg_on_fail="Error occurred while computing applicable children resource types.",
                                      content={"resource": rf.format_resource(resource, basic_info=True)})
    child_allowed = ax.evaluate_call(lambda: get_resource_child_allowed(resource),
                                     http_error=HTTPInternalServerError,
                                     msg_on_fail="Error occurred while computing allowed children resource status.",
                                     content={"resource": rf.format_resource(resource, basic_info=True)})
    data = {
        "resource_name": resource.resource_name,
        "resource_type": resource.resource_type_name,
        "children_resource_types": list(sorted(res_type.resource_type_name for res_type in res_types)),
        "children_resource_allowed": child_allowed,
        "root_service_id": svc.resource_id,
        "root_service_name": svc.resource_name,
        "root_service_type": svc.type,
    }
    return ax.valid_http(http_success=HTTPOk, content=data,
                         detail=s.ResourceTypes_GET_OkResponseSchema.description)


@s.PermissionsAPI.patch(schema=s.Permissions_PATCH_RequestSchema, tags=[s.PermissionTag],
                        response_schema=s.Permissions_PATCH_responses)
@view_config(route_name=s.PermissionsAPI.name, request_method="PATCH")
def update_permissions(request):
    # type: (AnyRequestType) -> AnyResponseType
    """
    Update the requested permissions and create missing related resources if necessary.
    """
    permissions = ar.get_value_multiformat_body_checked(request, "permissions", check_type=list)  # type: List[JSON]
    ax.verify_param(permissions, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                    msg_on_fail="No permissions to update (empty `permissions` parameter).")

    required_users = set()
    required_groups = set()
    has_permission_to_update = False
    for entry in permissions:
        ax.verify_param(entry, is_type=True, param_compare=dict, http_error=HTTPBadRequest,
                        msg_on_fail="Permission entry should be of `dict` type, but type `{}` was found instead".format(
                            type(entry)),
                        param_content={"value": entry})
        if "permission" in entry and entry["permission"]:
            user = entry.get("user")
            group = entry.get("group")
            ax.verify_param(bool(user or group), is_true=True, http_error=HTTPBadRequest,
                            msg_on_fail="No user or group defined with the permission to update.",
                            param_content={"value": entry})
            has_permission_to_update = True
            if user:
                required_users.add(user)
            if group:
                required_groups.add(group)

    for user_name in required_users:
        user = UserService.by_user_name(user_name, db_session=request.db)
        ax.verify_param(user, not_none=True, http_error=HTTPBadRequest,
                        msg_on_fail="Permission's user `{}` could not be found in the database.".format(user_name))
        uu.check_user_editable(user, request)
    for group_name in required_groups:
        ax.verify_param(GroupService.by_group_name(group_name, db_session=request.db),
                        not_none=True, http_error=HTTPBadRequest,
                        msg_on_fail="Permission's group `{}` could not be found in the database.".format(group_name))

    ax.verify_param(has_permission_to_update, is_true=True, http_error=HTTPBadRequest,
                    msg_on_fail="No permissions to update (none of the input entries has a defined permission).",
                    param_content={"value": permissions})

    # Reformat permissions config
    permissions_cfg = {"permissions": []}
    resource_full_path = ""
    resource_full_type = ""
    for i, entry in enumerate(permissions):
        resource_name = entry.get("resource_name")
        resource_type = entry.get("resource_type")
        permission = entry.get("permission")
        user = entry.get("user")
        group = entry.get("group")
        action = entry.get("action", "create")

        ax.verify_param(resource_name, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                        msg_on_fail="Missing `resource_name` parameter for permissions update.",
                        param_name="resource_name", param_content={"value": entry})
        ax.verify_param(resource_type, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                        msg_on_fail="Missing `resource_type` parameter for permissions update.",
                        param_name="resource_type", param_content={"value": entry})
        if i == 0:
            ax.verify_param(resource_type, is_equal=True, param_compare="service", http_error=HTTPBadRequest,
                            msg_on_fail="First resource in the permissions list should have a `service` type but has "
                                        "a `{}` type instead.".format(resource_type),
                            param_name="resource_type", param_content={"value": entry})
            service_name = resource_name
        else:
            resource_full_path += "/" + resource_name
            ax.verify_param(resource_type, not_equal=True, param_compare="service", http_error=HTTPBadRequest,
                            msg_on_fail="Only the first resource in the permissions list should be of `service` type.",
                            param_name="resource_type", param_content={"value": entry})
            resource_full_type += "/" + resource_type
        if permission:
            cfg_entry = {
                "service": service_name,  # noqa
                "resource": resource_full_path,
                "type": resource_type if resource_type == "service" else resource_full_type,
                "permission": permission,
                "action": action
            }
            if user:
                cfg_entry["user"] = user
            if group:
                cfg_entry["group"] = group

            permissions_cfg["permissions"].append(cfg_entry)

    # Apply permission update
    ax.evaluate_call(
        lambda: magpie_register_permissions_from_config(
            permissions_config=permissions_cfg, db_session=request.db, raise_errors=True),
        http_error=HTTPBadRequest, msg_on_fail="Failed to update requested permissions.")

    return ax.valid_http(http_success=HTTPOk, detail=s.Permissions_PATCH_OkResponseSchema.description)
