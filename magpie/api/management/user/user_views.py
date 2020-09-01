"""
User Views, both for specific user-name provided as request path variable and special keyword for logged session user.
"""
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPNotFound,
    HTTPOk
)
from pyramid.settings import asbool
from pyramid.view import view_config
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource import ResourceService
from ziggurat_foundations.models.services.user import UserService

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.service.service_formats import format_service_resources
from magpie.api.management.user import user_formats as uf
from magpie.api.management.user import user_utils as uu
from magpie.constants import MAGPIE_LOGGED_PERMISSION, MAGPIE_CONTEXT_PERMISSION, get_constant
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


@s.UsersAPI.get(tags=[s.UsersTag], response_schemas=s.Users_GET_responses)
@view_config(route_name=s.UsersAPI.name, request_method="GET")
def get_users_view(request):
    """
    List all registered user names.
    """
    user_name_list = ax.evaluate_call(lambda: [user.user_name for user in
                                               UserService.all(models.User, db_session=request.db)],
                                      fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                      msg_on_fail=s.Users_GET_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, content={"user_names": sorted(user_name_list)},
                         detail=s.Users_GET_OkResponseSchema.description)


@s.UsersAPI.post(schema=s.Users_POST_RequestSchema(), tags=[s.UsersTag], response_schemas=s.Users_POST_responses)
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


@s.UserAPI.patch(schema=s.User_PATCH_RequestSchema(), tags=[s.UsersTag], response_schemas=s.User_PATCH_responses)
@s.LoggedUserAPI.patch(schema=s.User_PATCH_RequestSchema(), tags=[s.LoggedUserTag],
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

    update_username = user.user_name != new_user_name and new_user_name is not None
    update_password = user.user_password != new_password and new_password is not None
    update_email = user.email != new_email and new_email is not None
    ax.verify_param(any([update_username, update_password, update_email]), is_true=True,
                    with_param=False,  # params are not useful in response for this case
                    content={"user_name": user.user_name},
                    http_error=HTTPBadRequest, msg_on_fail=s.User_PATCH_BadRequestResponseSchema.description)
    # user name change is admin-only operation
    if update_username:
        ax.verify_param(get_constant("MAGPIE_ADMIN_GROUP"), is_in=True,
                        param_compare=uu.get_user_groups_checked(request.user, request.db), with_param=False,
                        http_error=HTTPForbidden, msg_on_fail=s.User_PATCH_ForbiddenResponseSchema.description)

    # logged user updating itself is forbidden if it corresponds to special users
    # cannot edit reserved keywords nor apply them to another user
    forbidden_user_names = [
        get_constant("MAGPIE_ADMIN_USER", request),
        get_constant("MAGPIE_ANONYMOUS_USER", request),
        get_constant("MAGPIE_LOGGED_USER", request),
    ]
    check_user_name_cases = [user.user_name, new_user_name] if update_username else [user.user_name]
    for check_user_name in check_user_name_cases:
        ax.verify_param(check_user_name, not_in=True, param_compare=forbidden_user_names, param_name="user_name",
                        http_error=HTTPForbidden, content={"user_name": str(check_user_name)},
                        msg_on_fail=s.User_PATCH_ForbiddenResponseSchema.description)
    if update_username:
        uu.check_user_info(user_name=new_user_name, check_email=False, check_password=False, check_group=False)
        existing_user = ax.evaluate_call(lambda: UserService.by_user_name(new_user_name, db_session=request.db),
                                         fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                         msg_on_fail=s.User_PATCH_ForbiddenResponseSchema.description)
        ax.verify_param(existing_user, is_none=True, with_param=False, http_error=HTTPConflict,
                        msg_on_fail=s.User_PATCH_ConflictResponseSchema.description)
        user.user_name = new_user_name
    if update_email:
        uu.check_user_info(email=new_email, check_name=False, check_password=False, check_group=False)
        user.email = new_email
    if update_password:
        uu.check_user_info(password=new_password, check_name=False, check_email=False, check_group=False)
        UserService.set_password(user, new_password)
        UserService.regenerate_security_code(user)

    return ax.valid_http(http_success=HTTPOk, detail=s.Users_PATCH_OkResponseSchema.description)


@s.UserAPI.get(tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI, response_schemas=s.User_GET_responses)
@s.LoggedUserAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                     response_schemas=s.LoggedUser_GET_responses)
@view_config(route_name=s.UserAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_view(request):
    """
    Get user information by name.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    return ax.valid_http(http_success=HTTPOk, content={"user": uf.format_user(user)},
                         detail=s.User_GET_OkResponseSchema.description)


@s.UserAPI.delete(schema=s.User_DELETE_RequestSchema(), tags=[s.UsersTag], response_schemas=s.User_DELETE_responses)
@s.LoggedUserAPI.delete(schema=s.User_DELETE_RequestSchema(), tags=[s.LoggedUserTag],
                        response_schemas=s.LoggedUser_DELETE_responses)
@view_config(route_name=s.UserAPI.name, request_method="DELETE")  # FIXME: permission=MAGPIE_LOGGED_USER self-unregister
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
    return ax.valid_http(http_success=HTTPOk, detail=s.User_DELETE_OkResponseSchema.description)


@s.UserGroupsAPI.get(tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI, response_schemas=s.UserGroups_GET_responses)
@s.LoggedUserGroupsAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                           response_schemas=s.LoggedUserGroups_GET_responses)
@view_config(route_name=s.UserGroupsAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_groups_view(request):
    """
    List all groups a user belongs to.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    group_names = uu.get_user_groups_checked(user, request.db)
    return ax.valid_http(http_success=HTTPOk, content={"group_names": group_names},
                         detail=s.UserGroups_GET_OkResponseSchema.description)


@s.UserGroupsAPI.post(schema=s.UserGroups_POST_RequestSchema(), tags=[s.UsersTag],
                      response_schemas=s.UserGroups_POST_responses)
@s.LoggedUserGroupsAPI.post(schema=s.UserGroups_POST_RequestSchema(), tags=[s.LoggedUserTag],
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
    ax.verify_param(user.id, param_compare=[usr.id for usr in group.users], not_in=True, with_param=False,
                    http_error=HTTPConflict, content={"user_name": user.user_name, "group_name": group.group_name},
                    msg_on_fail=s.UserGroups_POST_ConflictResponseSchema.description)
    ax.evaluate_call(lambda: request.db.add(models.UserGroup(group_id=group.id, user_id=user.id)),  # noqa
                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.UserGroups_POST_RelationshipForbiddenResponseSchema.description,
                     content={"user_name": user.user_name, "group_name": group.group_name})
    return ax.valid_http(http_success=HTTPCreated, detail=s.UserGroups_POST_CreatedResponseSchema.description,
                         content={"user_name": user.user_name, "group_name": group.group_name})


@s.UserGroupAPI.delete(schema=s.UserGroup_DELETE_RequestSchema(), tags=[s.UsersTag],
                       response_schemas=s.UserGroup_DELETE_responses)
@s.LoggedUserGroupAPI.delete(schema=s.UserGroup_DELETE_RequestSchema(), tags=[s.LoggedUserTag],
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
                        tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                        response_schemas=s.UserResources_GET_responses)
@s.LoggedUserResourcesAPI.get(schema=s.UserResources_GET_RequestSchema(),
                              tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                              response_schemas=s.LoggedUserResources_GET_responses)
@view_config(route_name=s.UserResourcesAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_resources_view(request):
    """
    List all resources a user has permissions on.
    """
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit") or ar.get_query_param(request, "inherited"))
    user = ar.get_user_matchdict_checked_or_logged(request)
    db = request.db

    def build_json_user_resource_tree(usr):
        json_res = {}
        services = ResourceService.all(models.Service, db_session=db)
        for svc in services:
            svc_perms = uu.get_user_service_permissions(
                user=usr, service=svc, request=request, inherit_groups_permissions=inherit_groups_perms)
            if svc.type not in json_res:
                json_res[svc.type] = {}
            res_perms_dict = uu.get_user_service_resources_permissions_dict(
                user=usr, service=svc, request=request, inherit_groups_permissions=inherit_groups_perms)
            json_res[svc.type][svc.resource_name] = format_service_resources(
                svc,
                db_session=db,
                service_perms=svc_perms,
                resources_perms_dict=res_perms_dict,
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
                                  tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                  response_schemas=s.UserResourcePermissions_GET_responses)
@s.LoggedUserResourcePermissionsAPI.get(schema=s.UserResourcePermissions_GET_RequestSchema(),
                                        tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                        response_schemas=s.LoggedUserResourcePermissions_GET_responses)
@view_config(route_name=s.UserResourcePermissionsAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_resource_permissions_view(request):
    """
    List all permissions a user has on a specific resource.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request, "resource_id")
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit") or ar.get_query_param(request, "inherited"))
    effective_perms = asbool(ar.get_query_param(request, "effective"))
    return uu.get_user_resource_permissions_response(user, resource, request,
                                                     inherit_groups_permissions=inherit_groups_perms,
                                                     effective_permissions=effective_perms)


@s.UserResourcePermissionsAPI.post(schema=s.UserResourcePermissions_POST_RequestSchema(), tags=[s.UsersTag],
                                   response_schemas=s.UserResourcePermissions_POST_responses)
@s.LoggedUserResourcePermissionsAPI.post(schema=s.UserResourcePermissions_POST_RequestSchema(), tags=[s.LoggedUserTag],
                                         response_schemas=s.LoggedUserResourcePermissions_POST_responses)
@view_config(route_name=s.UserResourcePermissionsAPI.name, request_method="POST")
def create_user_resource_permission_view(request):
    """
    Create a permission on specific resource for a user.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, resource)
    return uu.create_user_resource_permission_response(user, resource, permission, request.db)


@s.UserResourcePermissionAPI.delete(schema=s.UserResourcePermission_DELETE_RequestSchema(), tags=[s.UsersTag],
                                    response_schemas=s.UserResourcePermission_DELETE_responses)
@s.LoggedUserResourcePermissionAPI.delete(schema=s.UserResourcePermission_DELETE_RequestSchema(),
                                          tags=[s.LoggedUserTag],
                                          response_schemas=s.LoggedUserResourcePermission_DELETE_responses)
@view_config(route_name=s.UserResourcePermissionAPI.name, request_method="DELETE")
def delete_user_resource_permission_view(request):
    """
    Delete an applied permission on a resource for a user (not including his groups permissions).
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, resource)
    return uu.delete_user_resource_permission_response(user, resource, permission, request.db)


@s.UserServicesAPI.get(tags=[s.UsersTag], schema=s.UserServices_GET_RequestSchema,
                       api_security=s.SecurityEveryoneAPI, response_schemas=s.UserServices_GET_responses)
@s.LoggedUserServicesAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                             response_schemas=s.LoggedUserServices_GET_responses)
@view_config(route_name=s.UserServicesAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_services_view(request):
    """
    List all services a user has permissions on.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    cascade_resources = asbool(ar.get_query_param(request, "cascade"))
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit") or ar.get_query_param(request, "inherited"))
    format_as_list = asbool(ar.get_query_param(request, "flatten"))

    svc_json = uu.get_user_services(user, request=request,
                                    cascade_resources=cascade_resources,
                                    inherit_groups_permissions=inherit_groups_perms,
                                    format_as_list=format_as_list)
    return ax.valid_http(http_success=HTTPOk, content={"services": svc_json},
                         detail=s.UserServices_GET_OkResponseSchema.description)


@s.UserServicePermissionsAPI.get(schema=s.UserServicePermissions_GET_RequestSchema,
                                 tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                 response_schemas=s.UserServicePermissions_GET_responses)
@s.LoggedUserServicePermissionsAPI.get(schema=s.UserServicePermissions_GET_RequestSchema,
                                       tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                       response_schemas=s.LoggedUserServicePermissions_GET_responses)
@view_config(route_name=s.UserServicePermissionsAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_service_permissions_view(request):
    """
    List all permissions a user has on a service.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit") or ar.get_query_param(request, "inherited"))
    perms = ax.evaluate_call(lambda: uu.get_user_service_permissions(service=service, user=user, request=request,
                                                                     inherit_groups_permissions=inherit_groups_perms),
                             fallback=lambda: request.db.rollback(), http_error=HTTPNotFound,
                             msg_on_fail=s.UserServicePermissions_GET_NotFoundResponseSchema.description,
                             content={"service_name": str(service.resource_name), "user_name": str(user.user_name)})
    return ax.valid_http(http_success=HTTPOk, detail=s.UserServicePermissions_GET_OkResponseSchema.description,
                         content={"permission_names": sorted(p.value for p in perms)})


@s.UserServicePermissionsAPI.post(schema=s.UserServicePermissions_POST_RequestSchema, tags=[s.UsersTag],
                                  response_schemas=s.UserServicePermissions_POST_responses)
@s.LoggedUserServicePermissionsAPI.post(schema=s.UserServicePermissions_POST_RequestSchema, tags=[s.LoggedUserTag],
                                        response_schemas=s.LoggedUserServicePermissions_POST_responses)
@view_config(route_name=s.UserServicePermissionsAPI.name, request_method="POST")
def create_user_service_permission_view(request):
    """
    Create a permission on a service for a user.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_multiformat_body_checked(request, service)
    return uu.create_user_resource_permission_response(user, service, permission, request.db)


@s.UserServicePermissionAPI.delete(schema=s.UserServicePermission_DELETE_RequestSchema, tags=[s.UsersTag],
                                   response_schemas=s.UserServicePermission_DELETE_responses)
@s.LoggedUserServicePermissionAPI.delete(schema=s.UserServicePermission_DELETE_RequestSchema, tags=[s.LoggedUserTag],
                                         response_schemas=s.LoggedUserServicePermission_DELETE_responses)
@view_config(route_name=s.UserServicePermissionAPI.name, request_method="DELETE")
def delete_user_service_permission_view(request):
    """
    Delete an applied permission on a service for a user (not including his groups permissions).
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, service)
    return uu.delete_user_resource_permission_response(user, service, permission, request.db)


@s.UserServiceResourcesAPI.get(schema=s.UserServiceResources_GET_RequestSchema,
                               tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                               response_schemas=s.UserServiceResources_GET_responses)
@s.LoggedUserServiceResourcesAPI.get(schema=s.UserServiceResources_GET_RequestSchema,
                                     tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                     response_schemas=s.LoggedUserServiceResources_GET_responses)
@view_config(route_name=s.UserServiceResourcesAPI.name, request_method="GET", permission=MAGPIE_CONTEXT_PERMISSION)
def get_user_service_resources_view(request):
    """
    List all resources under a service a user has permission on.
    """
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit") or ar.get_query_param(request, "inherited"))
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    service_perms = uu.get_user_service_permissions(
        user, service, request=request, inherit_groups_permissions=inherit_groups_perms)
    resources_perms_dict = uu.get_user_service_resources_permissions_dict(
        user, service, request=request, inherit_groups_permissions=inherit_groups_perms)
    user_svc_res_json = format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=service_perms,
        resources_perms_dict=resources_perms_dict,
        show_all_children=False,
        show_private_url=False,
    )
    return ax.valid_http(http_success=HTTPOk, content={"service": user_svc_res_json},
                         detail=s.UserServiceResources_GET_OkResponseSchema.description)
