"""
User Views, both for specific user-name provided as request path variable and special keyword for logged session user.
"""
from pyramid.httpexceptions import HTTPBadRequest, HTTPCreated, HTTPForbidden, HTTPNotFound, HTTPOk
from pyramid.settings import asbool
from pyramid.view import view_config
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource import ResourceService

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.service import service_formats as sf
from magpie.api.management.service import service_utils as su
from magpie.api.management.user import user_formats as uf
from magpie.api.management.user import user_utils as uu
from magpie.api.webhooks import WebhookAction, process_webhook_requests
from magpie.constants import MAGPIE_CONTEXT_PERMISSION, MAGPIE_LOGGED_PERMISSION, get_constant
from magpie.permissions import PermissionType, format_permissions
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


@s.UsersAPI.get(schema=s.Users_GET_RequestSchema, tags=[s.UsersTag], response_schemas=s.Users_GET_responses)
@view_config(route_name=s.UsersAPI.name, request_method="GET")
def get_users_view(request):
    """
    List all registered user names or details.
    """
    query = request.params.get("status")
    status = None
    if query is not None:
        status = models.UserStatuses.get(query)
        allowed = models.UserStatuses.allowed()
        ax.verify_param(status, not_none=True, param_name="status",
                        param_content={"compare": allowed},  # provide literals in error response
                        http_error=HTTPBadRequest, msg_on_fail=s.Users_GET_BadRequestSchema.description)
    detail = asbool(request.params.get("detail", False))
    user_list = ax.evaluate_call(lambda: models.UserSearchService.by_status(status, db_session=request.db),
                                 fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                 msg_on_fail=s.Users_GET_ForbiddenResponseSchema.description)
    if detail:
        data = {"users": list(sorted([uf.format_user(user, basic_info=True) for user in user_list],
                                     key=lambda user: user["user_name"]))}
    else:
        data = {"user_names": list(sorted(user.user_name for user in user_list))}
    return ax.valid_http(http_success=HTTPOk, content=data, detail=s.Users_GET_OkResponseSchema.description)


@s.UsersAPI.post(schema=s.Users_POST_RequestSchema, tags=[s.UsersTag], response_schemas=s.Users_POST_responses)
@view_config(route_name=s.UsersAPI.name, request_method="POST")
def create_user_view(request):
    """
    Create a new user.
    """
    user_name = ar.get_multiformat_body(request, "user_name")
    email = ar.get_multiformat_body(request, "email")
    password = ar.get_multiformat_body(request, "password")
    group_name = ar.get_multiformat_body(request, "group_name")
    return uu.create_user(user_name, password, email, group_name, db_session=request.db)


@s.UserAPI.patch(schema=s.User_PATCH_RequestSchema, tags=[s.UsersTag], response_schemas=s.User_PATCH_responses)
@s.LoggedUserAPI.patch(schema=s.User_PATCH_RequestSchema, tags=[s.LoggedUserTag],
                       response_schemas=s.LoggedUser_PATCH_responses)
@view_config(route_name=s.UserAPI.name, request_method="PATCH", permission=MAGPIE_LOGGED_PERMISSION)
def update_user_view(request):
    """
    Update user information by user name.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    new_user_name = ar.get_multiformat_body(request, "user_name", default=user.user_name)
    new_email = ar.get_multiformat_body(request, "email", default=user.email)
    new_password = ar.get_multiformat_body(request, "password", default=user.user_password)
    new_status = models.UserStatuses.get(ar.get_multiformat_body(request, "status", default=None))
    uu.update_user(user, request, new_user_name, new_password, new_email, new_status)
    return ax.valid_http(http_success=HTTPOk, detail=s.Users_PATCH_OkResponseSchema.description)


@s.UserAPI.get(schema=s.User_GET_RequestSchema, tags=[s.UsersTag],
               response_schemas=s.User_GET_responses, api_security=s.SecurityAuthenticatedAPI)
@s.LoggedUserAPI.get(schema=s.User_GET_RequestSchema, tags=[s.LoggedUserTag],
                     response_schemas=s.LoggedUser_GET_responses, api_security=s.SecurityAuthenticatedAPI)
@view_config(route_name=s.UserAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_view(request):
    """
    Get user information by name.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    return ax.valid_http(http_success=HTTPOk, content={"user": uf.format_user(user)},
                         detail=s.User_GET_OkResponseSchema.description)


@s.UserAPI.delete(schema=s.User_DELETE_RequestSchema, tags=[s.UsersTag], response_schemas=s.User_DELETE_responses)
@s.LoggedUserAPI.delete(schema=s.User_DELETE_RequestSchema, tags=[s.LoggedUserTag],
                        response_schemas=s.LoggedUser_DELETE_responses)
@view_config(route_name=s.UserAPI.name, request_method="DELETE", permission=MAGPIE_LOGGED_PERMISSION)
def delete_user_view(request):
    """
    Delete a user by name.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    ax.verify_param(user.user_name, not_in=True, with_param=False,  # avoid leaking username details
                    param_compare=[get_constant("MAGPIE_ADMIN_USER", request),
                                   get_constant("MAGPIE_ANONYMOUS_USER", request)],
                    http_error=HTTPForbidden, msg_on_fail=s.User_DELETE_ForbiddenResponseSchema.description)
    ax.evaluate_call(lambda: request.db.delete(user), fallback=lambda: request.db.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.User_DELETE_ForbiddenResponseSchema.description)

    # Process any webhook requests
    webhook_params = {"user.name": user.user_name, "user.id": user.id, "user.email": user.email}
    process_webhook_requests(WebhookAction.DELETE_USER, webhook_params)

    return ax.valid_http(http_success=HTTPOk, detail=s.User_DELETE_OkResponseSchema.description)


@s.UserGroupsAPI.get(schema=s.UserGroups_GET_RequestSchema, tags=[s.UsersTag],
                     response_schemas=s.UserGroups_GET_responses, api_security=s.SecurityAuthenticatedAPI)
@s.LoggedUserGroupsAPI.get(schema=s.UserGroups_GET_RequestSchema, tags=[s.LoggedUserTag],
                           response_schemas=s.LoggedUserGroups_GET_responses, api_security=s.SecurityAuthenticatedAPI)
@view_config(route_name=s.UserGroupsAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_groups_view(request):
    """
    List all groups a user belongs to.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    group_names = uu.get_user_groups_checked(user, request.db)
    return ax.valid_http(http_success=HTTPOk, content={"group_names": group_names},
                         detail=s.UserGroups_GET_OkResponseSchema.description)


@s.UserGroupsAPI.post(schema=s.UserGroups_POST_RequestSchema, tags=[s.UsersTag],
                      response_schemas=s.UserGroups_POST_responses)
@s.LoggedUserGroupsAPI.post(schema=s.UserGroups_POST_RequestSchema, tags=[s.LoggedUserTag],
                            response_schemas=s.LoggedUserGroups_POST_responses)
@view_config(route_name=s.UserGroupsAPI.name, request_method="POST")
def assign_user_group_view(request):
    """
    Assign a user to a group.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)

    group_name = ar.get_value_multiformat_body_checked(request, "group_name")
    group = ax.evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=request.db),
                             fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                             msg_on_fail=s.UserGroups_POST_ForbiddenResponseSchema.description)
    ax.verify_param(group, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.UserGroups_POST_GroupNotFoundResponseSchema.description)
    uu.assign_user_group(user, group, db_session=request.db)
    return ax.valid_http(http_success=HTTPCreated, detail=s.UserGroups_POST_CreatedResponseSchema.description,
                         content={"user_name": user.user_name, "group_name": group.group_name})


@s.UserGroupAPI.delete(schema=s.UserGroup_DELETE_RequestSchema, tags=[s.UsersTag],
                       response_schemas=s.UserGroup_DELETE_responses)
@s.LoggedUserGroupAPI.delete(schema=s.UserGroup_DELETE_RequestSchema, tags=[s.LoggedUserTag],
                             response_schemas=s.LoggedUserGroup_DELETE_responses)
@view_config(route_name=s.UserGroupAPI.name, request_method="DELETE")
def delete_user_group_view(request):
    """
    Removes a user from a group.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    group = ar.get_group_matchdict_checked(request)
    uu.delete_user_group(user, group, request.db)
    return ax.valid_http(http_success=HTTPOk, detail=s.UserGroup_DELETE_OkResponseSchema.description)


@s.UserResourcesAPI.get(schema=s.UserResources_GET_RequestSchema(),
                        tags=[s.UsersTag], api_security=s.SecurityAuthenticatedAPI,
                        response_schemas=s.UserResources_GET_responses)
@s.LoggedUserResourcesAPI.get(schema=s.UserResources_GET_RequestSchema(),
                              tags=[s.LoggedUserTag], api_security=s.SecurityAuthenticatedAPI,
                              response_schemas=s.LoggedUserResources_GET_responses)
@view_config(route_name=s.UserResourcesAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_resources_view(request):
    """
    List all resources a user has permissions on.
    """
    inherit_groups_perms = asbool(ar.get_query_param(request, ["inherit", "inherited"]))
    resolve_groups_perms = asbool(ar.get_query_param(request, ["resolve", "resolved"]))
    filtered_perms = asbool(ar.get_query_param(request, ["filter", "filtered"]))
    service_types = ar.get_query_param(request, ["type", "types"], default="")
    service_types = su.filter_service_types(service_types, default_services=True)
    user = ar.get_user_matchdict_checked_or_logged(request)
    db = request.db

    # skip admin-only full listing of resources if filtered view is requested
    is_admin = False
    if not filtered_perms and request.user is not None:
        admin_group = get_constant("MAGPIE_ADMIN_GROUP", settings_container=request)
        is_admin = admin_group in [group.group_name for group in request.user.groups]

    def build_json_user_resource_tree(usr):
        json_res = {}
        perm_type = PermissionType.INHERITED if inherit_groups_perms else PermissionType.DIRECT
        services = ResourceService.all(models.Service, db_session=db)
        services = services.filter(models.Service.type.in_(service_types))  # pylint: disable=E1101,no-member
        # add service-types so they are ordered and listed if no service of that type was defined
        for svc_type in sorted(service_types):
            json_res[svc_type] = {}
        for svc in services:
            svc_perms = uu.get_user_service_permissions(
                user=usr, service=svc, request=request,
                inherit_groups_permissions=inherit_groups_perms, resolve_groups_permissions=resolve_groups_perms)
            res_perms_dict = uu.get_user_service_resources_permissions_dict(
                user=usr, service=svc, request=request,
                inherit_groups_permissions=inherit_groups_perms, resolve_groups_permissions=resolve_groups_perms)
            # always allow admin to view full resource tree, unless explicitly requested to be filtered
            # otherwise (non-admin), only add details if there is at least one resource permission (any level)
            if (is_admin and not filtered_perms) or (svc_perms or res_perms_dict):
                json_res[svc.type][svc.resource_name] = sf.format_service_resources(
                    svc,
                    db_session=db,
                    service_perms=svc_perms,
                    resources_perms_dict=res_perms_dict,
                    permission_type=perm_type,
                    show_all_children=False,
                    show_private_url=False,
                )
        return json_res

    usr_res_dict = ax.evaluate_call(lambda: build_json_user_resource_tree(user),
                                    fallback=lambda: db.rollback(), http_error=HTTPNotFound,
                                    msg_on_fail=s.UserResources_GET_NotFoundResponseSchema.description,
                                    content={"user_name": user.user_name,
                                             "resource_types": [models.Service.resource_type_name]})
    return ax.valid_http(http_success=HTTPOk, content={"resources": usr_res_dict},
                         detail=s.UserResources_GET_OkResponseSchema.description)


@s.UserResourcePermissionsAPI.get(schema=s.UserResourcePermissions_GET_RequestSchema(),
                                  tags=[s.UsersTag, s.PermissionTag], api_security=s.SecurityAuthenticatedAPI,
                                  response_schemas=s.UserResourcePermissions_GET_responses)
@s.LoggedUserResourcePermissionsAPI.get(schema=s.UserResourcePermissions_GET_RequestSchema(),
                                        tags=[s.LoggedUserTag, s.PermissionTag],
                                        api_security=s.SecurityAuthenticatedAPI,
                                        response_schemas=s.LoggedUserResourcePermissions_GET_responses)
@view_config(route_name=s.UserResourcePermissionsAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_resource_permissions_view(request):
    """
    List all permissions a user has on a specific resource.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request, "resource_id")
    inherit_groups_perms = asbool(ar.get_query_param(request, ["inherit", "inherited"]))
    resolve_groups_perms = asbool(ar.get_query_param(request, ["resolve", "resolved"]))
    effective_perms = asbool(ar.get_query_param(request, "effective"))
    return uu.get_user_resource_permissions_response(user, resource, request,
                                                     inherit_groups_permissions=inherit_groups_perms,
                                                     resolve_groups_permissions=resolve_groups_perms,
                                                     effective_permissions=effective_perms)


@s.UserResourcePermissionsAPI.post(schema=s.UserResourcePermissions_POST_RequestSchema,
                                   tags=[s.UsersTag, s.PermissionTag],
                                   response_schemas=s.UserResourcePermissions_POST_responses)
@s.LoggedUserResourcePermissionsAPI.post(schema=s.UserResourcePermissions_POST_RequestSchema,
                                         tags=[s.LoggedUserTag, s.PermissionTag],
                                         response_schemas=s.LoggedUserResourcePermissions_POST_responses)
@view_config(route_name=s.UserResourcePermissionsAPI.name, request_method="POST")
def create_user_resource_permissions_view(request):
    """
    Create a permission on specific resource for a user.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, resource)
    return uu.create_user_resource_permission_response(user, resource, permission, request.db, overwrite=False)


@s.UserResourcePermissionsAPI.put(schema=s.UserResourcePermissions_PUT_RequestSchema,
                                  tags=[s.UsersTag, s.PermissionTag],
                                  response_schemas=s.UserResourcePermissions_PUT_responses)
@s.LoggedUserResourcePermissionsAPI.put(schema=s.UserResourcePermissions_PUT_RequestSchema,
                                        tags=[s.LoggedUserTag, s.PermissionTag],
                                        response_schemas=s.LoggedUserResourcePermissions_PUT_responses)
@view_config(route_name=s.UserResourcePermissionsAPI.name, request_method="PUT")
def replace_user_resource_permissions_view(request):
    """
    Create or modify an existing permission on a resource for a user.

    Can be used to adjust permission modifiers.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, resource)
    return uu.create_user_resource_permission_response(user, resource, permission, request.db, overwrite=True)


@s.UserResourcePermissionsAPI.delete(schema=s.UserResourcePermissions_DELETE_RequestSchema,
                                     tags=[s.UsersTag, s.PermissionTag],
                                     response_schemas=s.UserResourcePermissions_DELETE_responses)
@s.LoggedUserResourcePermissionsAPI.delete(schema=s.UserResourcePermissions_DELETE_RequestSchema,
                                           tags=[s.LoggedUserTag, s.PermissionTag],
                                           response_schemas=s.LoggedUserResourcePermissions_DELETE_responses)
@view_config(route_name=s.UserResourcePermissionsAPI.name, request_method="DELETE")
def delete_user_resource_permissions_view(request):
    """
    Delete a permission from a specific resource for a user (not including his groups permissions).
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, resource)
    return uu.delete_user_resource_permission_response(user, resource, permission, request.db)


@s.UserResourcePermissionAPI.delete(schema=s.UserResourcePermissionName_DELETE_RequestSchema,
                                    tags=[s.UsersTag, s.PermissionTag],
                                    response_schemas=s.UserResourcePermissionName_DELETE_responses)
@s.LoggedUserResourcePermissionAPI.delete(schema=s.UserResourcePermissionName_DELETE_RequestSchema,
                                          tags=[s.LoggedUserTag, s.PermissionTag],
                                          response_schemas=s.LoggedUserResourcePermissionName_DELETE_responses)
@view_config(route_name=s.UserResourcePermissionAPI.name, request_method="DELETE")
def delete_user_resource_permission_name_view(request):
    """
    Delete a permission by name from a resource for a user (not including his groups permissions).
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, resource)
    return uu.delete_user_resource_permission_response(user, resource, permission, request.db)


@s.UserServicesAPI.get(schema=s.UserServices_GET_RequestSchema,
                       tags=[s.UsersTag], api_security=s.SecurityAuthenticatedAPI,
                       response_schemas=s.UserServices_GET_responses)
@s.LoggedUserServicesAPI.get(schema=s.UserServices_GET_RequestSchema,
                             tags=[s.LoggedUserTag], api_security=s.SecurityAuthenticatedAPI,
                             response_schemas=s.LoggedUserServices_GET_responses)
@view_config(route_name=s.UserServicesAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_services_view(request):
    """
    List all services a user has permissions on.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    cascade_resources = asbool(ar.get_query_param(request, "cascade"))
    inherit_groups_perms = asbool(ar.get_query_param(request, ["inherit", "inherited"]))
    resolve_groups_perms = asbool(ar.get_query_param(request, ["resolve", "resolved"]))
    format_as_list = asbool(ar.get_query_param(request, ["flatten", "list"]))
    service_types = ar.get_query_param(request, ["type", "types"], default="")
    service_types = su.filter_service_types(service_types)  # don't use default service types to populate response

    svc_json = uu.get_user_services(user, request=request,
                                    cascade_resources=cascade_resources,
                                    inherit_groups_permissions=inherit_groups_perms,
                                    resolve_groups_permissions=resolve_groups_perms,
                                    format_as_list=format_as_list,
                                    service_types=service_types)
    return ax.valid_http(http_success=HTTPOk, content={"services": svc_json},
                         detail=s.UserServices_GET_OkResponseSchema.description)


@s.UserServicePermissionsAPI.get(schema=s.UserServicePermissions_GET_RequestSchema(),
                                 tags=[s.UsersTag], api_security=s.SecurityAuthenticatedAPI,
                                 response_schemas=s.UserServicePermissions_GET_responses)
@s.LoggedUserServicePermissionsAPI.get(schema=s.UserServicePermissions_GET_RequestSchema(),
                                       tags=[s.LoggedUserTag], api_security=s.SecurityAuthenticatedAPI,
                                       response_schemas=s.LoggedUserServicePermissions_GET_responses)
@view_config(route_name=s.UserServicePermissionsAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_service_permissions_view(request):
    """
    List all permissions a user has on a service.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    inherit_groups_perms = asbool(ar.get_query_param(request, ["inherit", "inherited"]))
    resolve_groups_perms = asbool(ar.get_query_param(request, ["resolve", "resolved"]))
    perm_type = PermissionType.INHERITED if inherit_groups_perms else PermissionType.DIRECT
    perms = ax.evaluate_call(lambda: uu.get_user_service_permissions(service=service, user=user, request=request,
                                                                     inherit_groups_permissions=inherit_groups_perms,
                                                                     resolve_groups_permissions=resolve_groups_perms),
                             fallback=lambda: request.db.rollback(), http_error=HTTPNotFound,
                             msg_on_fail=s.UserServicePermissions_GET_NotFoundResponseSchema.description,
                             content={"service_name": str(service.resource_name), "user_name": str(user.user_name)})
    return ax.valid_http(http_success=HTTPOk, content=format_permissions(perms, perm_type),
                         detail=s.UserServicePermissions_GET_OkResponseSchema.description)


@s.UserServicePermissionsAPI.post(schema=s.UserServicePermissions_POST_RequestSchema,
                                  tags=[s.UsersTag, s.PermissionTag],
                                  response_schemas=s.UserServicePermissions_POST_responses)
@s.LoggedUserServicePermissionsAPI.post(schema=s.UserServicePermissions_POST_RequestSchema,
                                        tags=[s.LoggedUserTag, s.PermissionTag],
                                        response_schemas=s.LoggedUserServicePermissions_POST_responses)
@view_config(route_name=s.UserServicePermissionsAPI.name, request_method="POST")
def create_user_service_permissions_view(request):
    """
    Create a permission on a service for a user.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, service)
    return uu.create_user_resource_permission_response(user, service, permission, request.db, overwrite=False)


@s.UserServicePermissionsAPI.put(schema=s.UserServicePermissions_PUT_RequestSchema,
                                 tags=[s.UsersTag, s.PermissionTag],
                                 response_schemas=s.UserServicePermissions_PUT_responses)
@s.LoggedUserServicePermissionsAPI.put(schema=s.UserServicePermissions_PUT_RequestSchema,
                                       tags=[s.LoggedUserTag, s.PermissionTag],
                                       response_schemas=s.LoggedUserServicePermissions_PUT_responses)
@view_config(route_name=s.UserServicePermissionsAPI.name, request_method="PUT")
def replace_user_service_permissions_view(request):
    """
    Create or modify an existing permission on a service for a user.

    Can be used to adjust permission modifiers.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, service)
    return uu.create_user_resource_permission_response(user, service, permission, request.db, overwrite=True)


@s.UserServicePermissionsAPI.delete(schema=s.UserServicePermissions_DELETE_RequestSchema,
                                    tags=[s.UsersTag, s.PermissionTag],
                                    response_schemas=s.UserServicePermissions_DELETE_responses)
@s.LoggedUserServicePermissionsAPI.delete(schema=s.UserServicePermissions_DELETE_RequestSchema,
                                          tags=[s.LoggedUserTag, s.PermissionTag],
                                          response_schemas=s.LoggedUserServicePermissions_DELETE_responses)
@view_config(route_name=s.UserServicePermissionsAPI.name, request_method="DELETE")
def delete_user_service_permissions_view(request):
    """
    Delete a permission from a service for a user (not including his groups permissions).
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, service)
    return uu.delete_user_resource_permission_response(user, service, permission, request.db)


@s.UserServicePermissionAPI.delete(schema=s.UserServicePermissionName_DELETE_RequestSchema,
                                   tags=[s.UsersTag, s.PermissionTag],
                                   response_schemas=s.UserServicePermissionName_DELETE_responses)
@s.LoggedUserServicePermissionAPI.delete(schema=s.UserServicePermissionName_DELETE_RequestSchema,
                                         tags=[s.LoggedUserTag, s.PermissionTag],
                                         response_schemas=s.LoggedUserServicePermissionName_DELETE_responses)
@view_config(route_name=s.UserServicePermissionAPI.name, request_method="DELETE")
def delete_user_service_permission_name_view(request):
    """
    Delete a permission by name from a service for a user (not including his groups permissions).
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, service)
    return uu.delete_user_resource_permission_response(user, service, permission, request.db)


@s.UserServiceResourcesAPI.get(schema=s.UserServiceResources_GET_RequestSchema,
                               tags=[s.UsersTag], api_security=s.SecurityAuthenticatedAPI,
                               response_schemas=s.UserServiceResources_GET_responses)
@s.LoggedUserServiceResourcesAPI.get(schema=s.UserServiceResources_GET_RequestSchema,
                                     tags=[s.LoggedUserTag], api_security=s.SecurityAuthenticatedAPI,
                                     response_schemas=s.LoggedUserServiceResources_GET_responses)
@view_config(route_name=s.UserServiceResourcesAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_service_resources_view(request):
    """
    List all resources under a service a user has permission on.
    """
    inherit_groups_perms = asbool(ar.get_query_param(request, ["inherit", "inherited"]))
    resolve_groups_perms = asbool(ar.get_query_param(request, ["resolve", "resolved"]))
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    service_perms = uu.get_user_service_permissions(
        user, service, request=request,
        inherit_groups_permissions=inherit_groups_perms,
        resolve_groups_permissions=resolve_groups_perms)
    resources_perms_dict = uu.get_user_service_resources_permissions_dict(
        user, service, request=request,
        inherit_groups_permissions=inherit_groups_perms,
        resolve_groups_permissions=resolve_groups_perms)
    user_svc_res_json = sf.format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=service_perms,
        resources_perms_dict=resources_perms_dict,
        permission_type=PermissionType.INHERITED if inherit_groups_perms else PermissionType.DIRECT,
        show_all_children=False,
        show_private_url=False,
    )
    return ax.valid_http(http_success=HTTPOk, content={"service": user_svc_res_json},
                         detail=s.UserServiceResources_GET_OkResponseSchema.description)
