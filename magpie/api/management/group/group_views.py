from pyramid.httpexceptions import HTTPBadRequest, HTTPConflict, HTTPForbidden, HTTPInternalServerError, HTTPOk
from pyramid.settings import asbool
from pyramid.view import view_config
from ziggurat_foundations.models.services.group import GroupService

from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.group import group_formats as gf
from magpie.api.management.group import group_utils as gu
from magpie.constants import get_constant


@s.GroupsAPI.get(tags=[s.GroupsTag], response_schemas=s.Groups_GET_responses)
@view_config(route_name=s.GroupsAPI.name, request_method="GET")
def get_groups_view(request):
    """
    Get list of group names.
    """
    group_names = gu.get_all_group_names(request.db)
    return ax.valid_http(http_success=HTTPOk, detail=s.Groups_GET_OkResponseSchema.description,
                         content={"group_names": group_names})


@s.GroupsAPI.post(schema=s.Groups_POST_RequestSchema, tags=[s.GroupsTag], response_schemas=s.Groups_POST_responses)
@view_config(route_name=s.GroupsAPI.name, request_method="POST")
def create_group_view(request):
    """
    Create a group.
    """
    group_name = ar.get_value_multiformat_body_checked(request, "group_name")
    group_desc = ar.get_multiformat_body(request, "description", default="")
    group_disc = asbool(ar.get_multiformat_body(request, "discoverable", default=False))
    group_terms = ar.get_multiformat_body(request, "terms", default="")
    return gu.create_group(group_name, group_desc, group_disc, group_terms, request.db)


@s.GroupAPI.get(schema=s.Group_GET_RequestSchema, tags=[s.GroupsTag], response_schemas=s.Group_GET_responses)
@view_config(route_name=s.GroupAPI.name, request_method="GET")
def get_group_view(request):
    """
    Get group information.
    """
    group = ar.get_group_matchdict_checked(request, group_name_key="group_name")
    return ax.valid_http(http_success=HTTPOk, detail=s.Group_GET_OkResponseSchema.description,
                         content={"group": gf.format_group(group, db_session=request.db)})


@s.GroupAPI.patch(schema=s.Group_PATCH_RequestSchema, tags=[s.GroupsTag], response_schemas=s.Group_PATCH_responses)
@view_config(route_name=s.GroupAPI.name, request_method="PATCH")
def edit_group_view(request):
    """
    Update a group by name.
    """
    group = ar.get_group_matchdict_checked(request, group_name_key="group_name")
    special_groups = [
        get_constant("MAGPIE_ANONYMOUS_GROUP", settings_container=request),
        get_constant("MAGPIE_ADMIN_GROUP", settings_container=request),
    ]
    ax.verify_param(group.group_name, not_in=True, param_compare=special_groups, param_name="group_name",
                    http_error=HTTPForbidden,
                    msg_on_fail=s.Group_PATCH_ReservedKeyword_ForbiddenResponseSchema.description)

    new_group_name = ar.get_multiformat_body(request, "group_name")
    new_description = ar.get_multiformat_body(request, "description")
    new_discoverability = ar.get_multiformat_body(request, "discoverable")
    if new_discoverability is not None:
        new_discoverability = asbool(new_discoverability)
    update_name = group.group_name != new_group_name and new_group_name is not None
    update_desc = group.description != new_description and new_description is not None
    update_disc = group.discoverable != new_discoverability and new_discoverability is not None
    ax.verify_param(any([update_name, update_desc, update_disc]), is_true=True,
                    with_param=False,  # params are not useful in response for this case
                    http_error=HTTPBadRequest, content={"group_name": group.group_name},
                    msg_on_fail=s.Group_PATCH_None_BadRequestResponseSchema.description)
    if update_name:
        ax.verify_param(new_group_name, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                        msg_on_fail=s.Group_PATCH_Name_BadRequestResponseSchema.description)
        group_name_size_range = range(1, 1 + get_constant("MAGPIE_GROUP_NAME_MAX_LENGTH", settings_container=request))
        ax.verify_param(len(new_group_name), is_in=True, param_compare=group_name_size_range,
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Group_PATCH_Size_BadRequestResponseSchema.description)
        ax.verify_param(GroupService.by_group_name(new_group_name, db_session=request.db),
                        is_none=True, http_error=HTTPConflict, with_param=False,  # don't return group as value
                        msg_on_fail=s.Group_PATCH_ConflictResponseSchema.description)
        group.group_name = new_group_name
    if update_desc:
        group.description = new_description
    if update_disc:
        group.discoverable = new_discoverability
    return ax.valid_http(http_success=HTTPOk, detail=s.Group_PATCH_OkResponseSchema.description)


@s.GroupAPI.delete(schema=s.Group_DELETE_RequestSchema, tags=[s.GroupsTag], response_schemas=s.Group_DELETE_responses)
@view_config(route_name=s.GroupAPI.name, request_method="DELETE")
def delete_group_view(request):
    """
    Delete a group by name.
    """
    group = ar.get_group_matchdict_checked(request)
    special_groups = [
        get_constant("MAGPIE_ANONYMOUS_GROUP", settings_container=request),
        get_constant("MAGPIE_ADMIN_GROUP", settings_container=request),
    ]
    ax.verify_param(group.group_name, not_in=True, param_compare=special_groups, param_name="group_name",
                    http_error=HTTPForbidden,
                    msg_on_fail=s.Group_DELETE_ReservedKeyword_ForbiddenResponseSchema.description)
    ax.evaluate_call(lambda: request.db.delete(group),
                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.Group_DELETE_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.Group_DELETE_OkResponseSchema.description)


@s.GroupUsersAPI.get(schema=s.GroupUsers_GET_RequestSchema, tags=[s.GroupsTag],
                     response_schemas=s.GroupUsers_GET_responses)
@view_config(route_name=s.GroupUsersAPI.name, request_method="GET")
def get_group_users_view(request):
    """
    List all user from a group.
    """
    group = ar.get_group_matchdict_checked(request)
    user_names = ax.evaluate_call(lambda: [user.user_name for user in group.users],
                                  http_error=HTTPForbidden,
                                  msg_on_fail=s.GroupUsers_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.GroupUsers_GET_OkResponseSchema.description,
                         content={"user_names": sorted(user_names)})


@s.GroupServicesAPI.get(schema=s.GroupServices_GET_RequestSchema, tags=[s.GroupsTag],
                        response_schemas=s.GroupServices_GET_responses)
@view_config(route_name=s.GroupServicesAPI.name, request_method="GET")
def get_group_services_view(request):
    """
    List all services a group has permission on.
    """
    group = ar.get_group_matchdict_checked(request)
    return gu.get_group_services_response(group, request.db)


@s.GroupServicePermissionsAPI.get(schema=s.GroupServicePermissions_GET_RequestSchema,
                                  tags=[s.GroupsTag, s.PermissionTag],
                                  response_schemas=s.GroupServicePermissions_GET_responses)
@view_config(route_name=s.GroupServicePermissionsAPI.name, request_method="GET")
def get_group_service_permissions_view(request):
    """
    List all permissions a group has on a specific service.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    return gu.get_group_service_permissions_response(group, service, request.db)


@s.GroupServicePermissionsAPI.post(schema=s.GroupServicePermissions_POST_RequestSchema,
                                   tags=[s.GroupsTag, s.PermissionTag],
                                   response_schemas=s.GroupServicePermissions_POST_responses)
@view_config(route_name=s.GroupServicePermissionsAPI.name, request_method="POST")
def create_group_service_permission_view(request):
    """
    Create a permission on a specific resource for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, service)
    return gu.create_group_resource_permission_response(group, service, permission, request.db, overwrite=False)


@s.GroupServicePermissionsAPI.put(schema=s.GroupServicePermissions_PUT_RequestSchema,
                                  tags=[s.GroupsTag, s.PermissionTag],
                                  response_schemas=s.GroupServicePermissions_PUT_responses)
@view_config(route_name=s.GroupServicePermissionsAPI.name, request_method="PUT")
def replace_group_service_permissions_view(request):
    """
    Create or modify an existing permission on a service for a group.

    Can be used to adjust permission modifiers.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, service)
    return gu.create_group_resource_permission_response(group, service, permission, request.db, overwrite=True)


@s.GroupServicePermissionsAPI.delete(schema=s.GroupServicePermissions_DELETE_RequestSchema,
                                     tags=[s.GroupsTag, s.PermissionTag],
                                     response_schemas=s.GroupServicePermissions_DELETE_responses)
@view_config(route_name=s.GroupServicePermissionsAPI.name, request_method="DELETE")
def delete_group_service_permission_view(request):
    """
    Delete a permission from a specific resource for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, service)
    return gu.delete_group_resource_permission_response(group, service, permission, db_session=request.db)


@s.GroupServicePermissionAPI.delete(schema=s.GroupServicePermissionName_DELETE_RequestSchema,
                                    tags=[s.GroupsTag, s.PermissionTag],
                                    response_schemas=s.GroupServicePermissionName_DELETE_responses)
@view_config(route_name=s.GroupServicePermissionAPI.name, request_method="DELETE")
def delete_group_service_permission_name_view(request):
    """
    Delete a permission by name from a specific service for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, service)
    return gu.delete_group_resource_permission_response(group, service, permission, db_session=request.db)


@s.GroupResourcesAPI.get(schema=s.GroupResources_GET_RequestSchema, tags=[s.GroupsTag],
                         response_schemas=s.GroupResources_GET_responses)
@view_config(route_name=s.GroupResourcesAPI.name, request_method="GET")
def get_group_resources_view(request):
    """
    List all resources a group has permission on.
    """
    group = ar.get_group_matchdict_checked(request)
    grp_res_json = ax.evaluate_call(lambda: gu.get_group_resources(group, request.db),
                                    fallback=lambda: request.db.rollback(),
                                    http_error=HTTPInternalServerError, content={"group": repr(group)},
                                    msg_on_fail=s.GroupResources_GET_InternalServerErrorResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.GroupResources_GET_OkResponseSchema.description,
                         content={"resources": grp_res_json})


@s.GroupResourcePermissionsAPI.get(schema=s.GroupResourcePermissions_GET_RequestSchema,
                                   tags=[s.GroupsTag, s.PermissionTag],
                                   response_schemas=s.GroupResourcePermissions_GET_responses)
@view_config(route_name=s.GroupResourcePermissionsAPI.name, request_method="GET")
def get_group_resource_permissions_view(request):
    """
    List all permissions a group has on a specific resource.
    """
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    return gu.get_group_resource_permissions_response(group, resource, db_session=request.db)


@s.GroupResourcePermissionsAPI.post(schema=s.GroupResourcePermissions_POST_RequestSchema,
                                    tags=[s.GroupsTag, s.PermissionTag],
                                    response_schemas=s.GroupResourcePermissions_POST_responses)
@view_config(route_name=s.GroupResourcePermissionsAPI.name, request_method="POST")
def create_group_resource_permissions_view(request):
    """
    Create a permission on a specific resource for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, resource)
    return gu.create_group_resource_permission_response(group, resource, permission, db_session=request.db)


@s.GroupResourcePermissionsAPI.put(schema=s.GroupResourcePermissions_PUT_RequestSchema,
                                   tags=[s.GroupsTag, s.PermissionTag],
                                   response_schemas=s.GroupResourcePermissions_PUT_responses)
@view_config(route_name=s.GroupResourcePermissionsAPI.name, request_method="PUT")
def replace_group_resource_permissions_view(request):
    """
    Create or modify an existing permission on a resource for a group.

    Can be used to adjust permission modifiers.
    """
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, resource)
    return gu.create_group_resource_permission_response(group, resource, permission, request.db, overwrite=True)


@s.GroupResourcePermissionsAPI.delete(schema=s.GroupResourcePermissions_DELETE_RequestSchema,
                                      tags=[s.GroupsTag, s.PermissionTag],
                                      response_schemas=s.GroupResourcePermissions_DELETE_responses)
@view_config(route_name=s.GroupResourcePermissionsAPI.name, request_method="DELETE")
def delete_group_resource_permissions_view(request):
    """
    Delete a permission from a specific resource for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, resource)
    return gu.delete_group_resource_permission_response(group, resource, permission, db_session=request.db)


@s.GroupResourcePermissionAPI.delete(schema=s.GroupResourcePermissionName_DELETE_RequestSchema,
                                     tags=[s.GroupsTag, s.PermissionTag],
                                     response_schemas=s.GroupResourcePermissionName_DELETE_responses)
@view_config(route_name=s.GroupResourcePermissionAPI.name, request_method="DELETE")
def delete_group_resource_permission_name_view(request):
    """
    Delete a permission by name from a specific resource for a group.
    """
    group = ar.get_group_matchdict_checked(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, resource)
    return gu.delete_group_resource_permission_response(group, resource, permission, db_session=request.db)


@s.GroupServiceResourcesAPI.get(schema=s.GroupServiceResources_GET_RequestSchema,
                                tags=[s.GroupsTag, s.PermissionTag],
                                response_schemas=s.GroupServiceResources_GET_responses)
@view_config(route_name=s.GroupServiceResourcesAPI.name, request_method="GET")
def get_group_service_resources_view(request):
    """
    List all resources under a service a group has permission on.
    """
    group = ar.get_group_matchdict_checked(request)
    service = ar.get_service_matchdict_checked(request)
    return gu.get_group_service_resources_response(group, service, request.db)
