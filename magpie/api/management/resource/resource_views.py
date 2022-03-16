from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict, HTTPForbidden, HTTPInternalServerError, HTTPNotFound, HTTPOk
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
from magpie.api.management.service.service_formats import format_service_resources
from magpie.api.management.service.service_utils import get_services_by_type
from magpie.permissions import PermissionType, format_permissions
from magpie.register import sync_services_phoenix, magpie_register_permissions_from_config
from magpie.services import SERVICE_TYPE_DICT, get_resource_child_allowed


@s.ResourcesAPI.get(tags=[s.ResourcesTag], response_schemas=s.Resources_GET_responses)
@view_config(route_name=s.ResourcesAPI.name, request_method="GET")
def get_resources_view(request):
    """
    List all registered resources.
    """
    res_json = {}
    for svc_type in SERVICE_TYPE_DICT:
        services = get_services_by_type(svc_type, db_session=request.db)
        res_json[svc_type] = {}
        for svc in services:
            res_json[svc_type][svc.resource_name] = format_service_resources(
                svc, request.db, show_all_children=True, show_private_url=False)
    res_json = {"resources": res_json}
    return ax.valid_http(http_success=HTTPOk, detail=s.Resources_GET_OkResponseSchema.description, content=res_json)


@s.ResourceAPI.get(schema=s.Resource_GET_RequestSchema, tags=[s.ResourcesTag],
                   response_schemas=s.Resource_GET_responses)
@view_config(route_name=s.ResourceAPI.name, request_method="GET")
def get_resource_view(request):
    """
    Get resource information.
    """
    resource = ar.get_resource_matchdict_checked(request)
    res_json = ax.evaluate_call(lambda: rf.format_resource_with_children(resource, db_session=request.db),
                                fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                                msg_on_fail=s.Resource_GET_InternalServerErrorResponseSchema.description,
                                content={"resource": rf.format_resource(resource, basic_info=False)})
    return ax.valid_http(http_success=HTTPOk, content={"resource": res_json},
                         detail=s.Resource_GET_OkResponseSchema.description)


@s.ResourcesAPI.post(schema=s.Resources_POST_RequestSchema, tags=[s.ResourcesTag],
                     response_schemas=s.Resources_POST_responses)
@view_config(route_name=s.ResourcesAPI.name, request_method="POST")
def create_resource_view(request):
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
    """
    Unregister a resource.
    """
    return ru.delete_resource(request)


@s.ResourceAPI.patch(schema=s.Resource_PATCH_RequestSchema, tags=[s.ResourcesTag],
                     response_schemas=s.Resource_PATCH_responses)
@view_config(route_name=s.ResourceAPI.name, request_method="PATCH")
def update_resource(request):
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
    """
    Update the requested permissions.
    """
    permissions = ar.get_value_multiformat_body_checked(request, "permissions", check_type=list)
    ax.verify_param(permissions, not_none=True, not_empty=True,
                    http_error=HTTPBadRequest, msg_on_fail=s.Permissions_PATCH_BadRequestResponseSchema.description)

    for entry in permissions:
        # Check if user/group exists for each permission
        if "permission" in entry.keys() and entry["permission"]:
            if "user" in entry.keys():
                user = UserService.by_user_name(entry["user"], db_session=request.db)
                if user is None:
                    raise RuntimeError(f"User {entry['user']} not found in the database.")
            if "group" in entry.keys():
                group = GroupService.by_group_name(entry["group"], db_session=request.db)
                if group is None:
                    raise RuntimeError(f"Group {entry['group']} not found in the database.")

    # Reformat permissions for function
    permissions_cfg = {"permissions": []}
    resource_full_path = ""
    resource_full_type = ""
    for i, entry in enumerate(permissions):
        resource_name = entry.get("resource_name")
        resource_type = entry.get("resource_type")
        permission = entry.get("permission")  # TODO: should verify if either dict or string, should maybe verify other fields?
        user = entry.get("user")
        group = entry.get("group")
        action = entry.get("action", "create")

        ax.verify_param(resource_name, not_none=True,
                        http_error=HTTPBadRequest, msg_on_fail=s.Permissions_PATCH_BadRequestResponseSchema.description)
        ax.verify_param(resource_type, not_none=True,
                        http_error=HTTPBadRequest, msg_on_fail=s.Permissions_PATCH_BadRequestResponseSchema.description)
        if i == 0:
            # First resource must be a service
            ax.verify_param(resource_type, is_equal=True, param_compare="service",
                            http_error=HTTPBadRequest, msg_on_fail=s.Permissions_PATCH_BadRequestResponseSchema.description)
            service_name = resource_name
        else:
            resource_full_path += "/" + resource_name
            # Other resources must not be services
            ax.verify_param(resource_type, not_equal=True, param_compare="service",
                            http_error=HTTPBadRequest, msg_on_fail=s.Permissions_PATCH_BadRequestResponseSchema.description)
            resource_full_type += "/" + resource_type
        if permission:
            # Check that a user and/or a group is defined
            ax.verify_param(bool(user or group), is_true=True,
                            http_error=HTTPBadRequest, msg_on_fail=s.Permissions_PATCH_BadRequestResponseSchema.description)
            cfg_entry = {
                "service": service_name,
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

    # apply permission update
    magpie_register_permissions_from_config(permissions_config=permissions_cfg, db_session=request.db)

    return ax.valid_http(http_success=HTTPOk, detail=s.Permissions_PATCH_OkResponseSchema.description)
