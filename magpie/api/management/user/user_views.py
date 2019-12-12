from magpie.api import exception as ax, requests as ar, schemas as s
from magpie.api.management.user import user_utils as uu, user_formats as uf
from magpie.api.management.service.service_formats import format_service_resources
from magpie.constants import get_constant
from magpie.definitions.pyramid_definitions import (
    asbool,
    view_config,
    HTTPOk,
    HTTPCreated,
    HTTPMovedPermanently,
    HTTPBadRequest,
    HTTPForbidden,
    HTTPNotFound,
    HTTPConflict,
    NO_PERMISSION_REQUIRED,
)
from magpie.definitions.ziggurat_definitions import UserService, GroupService, ResourceService
from magpie.utils import get_logger
from magpie import models
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
    return ax.valid_http(http_success=HTTPOk, content={u"user_names": sorted(user_name_list)},
                         detail=s.Users_GET_OkResponseSchema.description)


@s.UsersAPI.post(schema=s.Users_POST_RequestSchema(), tags=[s.UsersTag], response_schemas=s.Users_POST_responses)
@view_config(route_name=s.UsersAPI.name, request_method="POST")
def create_user_view(request):
    """
    Create a new user.
    """
    user_name = ar.get_multiformat_post(request, "user_name")
    email = ar.get_multiformat_post(request, "email")
    password = ar.get_multiformat_post(request, "password")
    group_name = ar.get_multiformat_post(request, "group_name")
    uu.check_user_info(user_name, email, password, group_name)
    return uu.create_user(user_name, password, email, group_name, db_session=request.db)


@s.UserAPI.put(schema=s.User_PUT_RequestSchema(), tags=[s.UsersTag], response_schemas=s.User_PUT_responses)
@s.LoggedUserAPI.put(schema=s.User_PUT_RequestSchema(), tags=[s.LoggedUserTag],
                     response_schemas=s.LoggedUser_PUT_responses)
@view_config(route_name=s.UserAPI.name, request_method="PUT")
def update_user_view(request):
    """
    Update user information by user name.
    """

    user_name = ar.get_value_matchdict_checked(request, key="user_name")
    ax.verify_param(user_name, param_compare=get_constant("MAGPIE_LOGGED_USER"), not_equal=True,
                    http_error=HTTPBadRequest, param_name="user_name", content={u"user_name": user_name},
                    msg_on_fail=s.Service_PUT_BadRequestResponseSchema_ReservedKeyword.description)

    user = ar.get_user_matchdict_checked(request, user_name_key="user_name")
    new_user_name = ar.get_multiformat_post(request, "user_name", default=user.user_name)
    new_email = ar.get_multiformat_post(request, "email", default=user.email)
    new_password = ar.get_multiformat_post(request, "password", default=user.user_password)
    uu.check_user_info(new_user_name, new_email, new_password, group_name=new_user_name)

    update_username = user.user_name != new_user_name
    update_password = user.user_password != new_password
    update_email = user.email != new_email
    ax.verify_param(any([update_username, update_password, update_email]), is_true=True, http_error=HTTPBadRequest,
                    content={u"user_name": user.user_name},
                    msg_on_fail=s.User_PUT_BadRequestResponseSchema.description)

    if user.user_name != new_user_name:
        existing_user = ax.evaluate_call(lambda: UserService.by_user_name(new_user_name, db_session=request.db),
                                         fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                         msg_on_fail=s.User_PUT_ForbiddenResponseSchema.description)
        ax.verify_param(existing_user, is_none=True, http_error=HTTPConflict,
                        msg_on_fail=s.User_PUT_ConflictResponseSchema.description)
        user.user_name = new_user_name
    if user.email != new_email:
        user.email = new_email
    if user.user_password != new_password and new_password is not None:
        UserService.set_password(user, new_password)
        UserService.regenerate_security_code(user)

    return ax.valid_http(http_success=HTTPOk, detail=s.Users_PUT_OkResponseSchema.description)


@s.UserAPI.get(tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI, response_schemas=s.User_GET_responses)
@s.LoggedUserAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                     response_schemas=s.LoggedUser_GET_responses)
@view_config(route_name=s.UserAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_view(request):
    """
    Get user information by name.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    return ax.valid_http(http_success=HTTPOk, content={u"user": uf.format_user(user)},
                         detail=s.User_GET_OkResponseSchema.description)


@s.UserAPI.delete(schema=s.User_DELETE_RequestSchema(), tags=[s.UsersTag], response_schemas=s.User_DELETE_responses)
@s.LoggedUserAPI.delete(schema=s.User_DELETE_RequestSchema(), tags=[s.LoggedUserTag],
                        response_schemas=s.LoggedUser_DELETE_responses)
@view_config(route_name=s.UserAPI.name, request_method="DELETE")
def delete_user_view(request):
    """
    Delete a user by name.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    ax.evaluate_call(lambda: request.db.delete(user), fallback=lambda: request.db.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.User_DELETE_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.User_DELETE_OkResponseSchema.description)


@s.UserGroupsAPI.get(tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI, response_schemas=s.UserGroups_GET_responses)
@s.LoggedUserGroupsAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                           response_schemas=s.LoggedUserGroups_GET_responses)
@view_config(route_name=s.UserGroupsAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_groups_view(request):
    """
    List all groups a user belongs to.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    group_names = uu.get_user_groups_checked(request, user)
    return ax.valid_http(http_success=HTTPOk, content={u"group_names": group_names},
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

    group_name = ar.get_value_multiformat_post_checked(request, "group_name")
    group = ax.evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=request.db),
                             fallback=lambda: request.db.rollback(),
                             http_error=HTTPForbidden, msg_on_fail=s.UserGroups_POST_ForbiddenResponseSchema.description)
    ax.verify_param(group, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.UserGroups_POST_GroupNotFoundResponseSchema.description)
    ax.verify_param(user.id, param_compare=[usr.id for usr in group.users], not_in=True, http_error=HTTPConflict,
                    content={u"user_name": user.user_name, u"group_name": group.group_name},
                    msg_on_fail=s.UserGroups_POST_ConflictResponseSchema.description)
    # noinspection PyArgumentList
    ax.evaluate_call(lambda: request.db.add(models.UserGroup(group_id=group.id, user_id=user.id)),
                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.UserGroups_POST_RelationshipForbiddenResponseSchema.description,
                     content={u"user_name": user.user_name, u"group_name": group.group_name})
    return ax.valid_http(http_success=HTTPCreated, detail=s.UserGroups_POST_CreatedResponseSchema.description,
                         content={u"user_name": user.user_name, u"group_name": group.group_name})


@s.UserGroupAPI.delete(schema=s.UserGroup_DELETE_RequestSchema(), tags=[s.UsersTag],
                       response_schemas=s.UserGroup_DELETE_responses)
@s.LoggedUserGroupAPI.delete(schema=s.UserGroup_DELETE_RequestSchema(), tags=[s.LoggedUserTag],
                             response_schemas=s.LoggedUserGroup_DELETE_responses)
@view_config(route_name=s.UserGroupAPI.name, request_method="DELETE")
def delete_user_group_view(request):
    """
    Remove a user from a group.
    """
    db = request.db
    user = ar.get_user_matchdict_checked_or_logged(request)
    group = ar.get_group_matchdict_checked(request)

    def del_usr_grp(usr, grp):
        db.query(models.UserGroup) \
            .filter(models.UserGroup.user_id == usr.id) \
            .filter(models.UserGroup.group_id == grp.id) \
            .delete()

    ax.evaluate_call(lambda: del_usr_grp(user, group), fallback=lambda: db.rollback(),
                     http_error=HTTPNotFound, msg_on_fail=s.UserGroup_DELETE_NotFoundResponseSchema.description,
                     content={u"user_name": user.user_name, u"group_name": group.group_name})
    return ax.valid_http(http_success=HTTPOk, detail=s.UserGroup_DELETE_OkResponseSchema.description)


@s.UserResourcesAPI.get(schema=s.UserResources_GET_RequestSchema(),
                        tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                        response_schemas=s.UserResources_GET_responses)
@s.LoggedUserResourcesAPI.get(schema=s.UserResources_GET_RequestSchema(),
                              tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                              response_schemas=s.LoggedUserResources_GET_responses)
@view_config(route_name=s.UserResourcesAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_resources_view(request):
    """
    List all resources a user has permissions on.
    """
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit"))
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
                                    content={u"user_name": user.user_name,
                                             u"resource_types": [models.Service.resource_type_name]})
    return ax.valid_http(http_success=HTTPOk, content={u"resources": usr_res_dict},
                         detail=s.UserResources_GET_OkResponseSchema.description)


@s.UserInheritedResourcesAPI.get(tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                 response_schemas=s.UserResources_GET_responses)
@s.LoggedUserInheritedResourcesAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                       response_schemas=s.LoggedUserResources_GET_responses)
@view_config(route_name=s.UserInheritedResourcesAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_inherited_resources_view(request):
    """[DEPRECATED: use '/users/{user_name}/resources?inherit=true']
    List all resources a user has permissions on with his inherited user and groups permissions."""
    LOGGER.warning("Route deprecated: [{0}], Instead Use: [{1}]"
                   .format(s.UserInheritedResourcesAPI.path, s.UserResourcesAPI.path + "?inherit=true"))
    return HTTPMovedPermanently(location=request.path.replace("/inherited_resources", "/resources?inherit=true"))


@s.UserResourcePermissionsAPI.get(schema=s.UserResourcePermissions_GET_RequestSchema(),
                                  tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                  response_schemas=s.UserResourcePermissions_GET_responses)
@s.LoggedUserResourcePermissionsAPI.get(schema=s.UserResourcePermissions_GET_RequestSchema(),
                                        tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                        response_schemas=s.LoggedUserResourcePermissions_GET_responses)
@view_config(route_name=s.UserResourcePermissionsAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_resource_permissions_view(request):
    """
    List all permissions a user has on a specific resource.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request, "resource_id")
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit"))
    effective_perms = asbool(ar.get_query_param(request, "effective"))
    return uu.get_user_resource_permissions_response(user, resource, request,
                                                     inherit_groups_permissions=inherit_groups_perms,
                                                     effective_permissions=effective_perms)


@s.UserResourceInheritedPermissionsAPI.get(tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                           response_schemas=s.UserResourcePermissions_GET_responses)
@s.LoggedUserResourceInheritedPermissionsAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                                 response_schemas=s.LoggedUserResourcePermissions_GET_responses)
@view_config(route_name=s.UserResourceInheritedPermissionsAPI.name, request_method="GET",
             permission=NO_PERMISSION_REQUIRED)
def get_user_resource_inherit_groups_permissions_view(request):
    """[DEPRECATED: use '/users/{user_name}/resources/{resource_id}/permissions?inherit=true']
    List all permissions a user has on a specific resource with his inherited user and groups permissions."""
    LOGGER.warning("Route deprecated: [{0}], Instead Use: [{1}]"
                   .format(s.UserResourceInheritedPermissionsAPI.path,
                           s.UserResourcePermissionsAPI.path + "?inherit=true"))
    return HTTPMovedPermanently(location=request.path.replace("/inherited_permissions", "/permissions?inherit=true"))


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
    permission = ar.get_permission_multiformat_post_checked(request, resource)
    return uu.create_user_resource_permission_response(user, resource, permission, request.db)


@s.UserResourcePermissionAPI.delete(schema=s.UserResourcePermission_DELETE_RequestSchema(), tags=[s.UsersTag],
                                    response_schemas=s.UserResourcePermission_DELETE_responses)
@s.LoggedUserResourcePermissionAPI.delete(schema=s.UserResourcePermission_DELETE_RequestSchema(),
                                          tags=[s.LoggedUserTag],
                                          response_schemas=s.LoggedUserResourcePermission_DELETE_responses)
@view_config(route_name=s.UserResourcePermissionAPI.name, request_method="DELETE")
def delete_user_resource_permission_view(request):
    """
    Delete a direct permission on a resource for a user (not including his groups permissions).
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    resource = ar.get_resource_matchdict_checked(request)
    permission = ar.get_permission_matchdict_checked(request, resource)
    return uu.delete_user_resource_permission_response(user, resource, permission, request.db)


@s.UserServicesAPI.get(tags=[s.UsersTag], schema=s.UserServices_GET_RequestSchema,
                       api_security=s.SecurityEveryoneAPI, response_schemas=s.UserServices_GET_responses)
@s.LoggedUserServicesAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                             response_schemas=s.LoggedUserServices_GET_responses)
@view_config(route_name=s.UserServicesAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_services_view(request):
    """
    List all services a user has permissions on.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    cascade_resources = asbool(ar.get_query_param(request, "cascade"))
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit"))
    format_as_list = asbool(ar.get_query_param(request, "list"))

    svc_json = uu.get_user_services(user, request=request,
                                    cascade_resources=cascade_resources,
                                    inherit_groups_permissions=inherit_groups_perms,
                                    format_as_list=format_as_list)
    return ax.valid_http(http_success=HTTPOk, content={u"services": svc_json},
                         detail=s.UserServices_GET_OkResponseSchema.description)


@s.UserInheritedServicesAPI.get(tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                response_schemas=s.UserServices_GET_responses)
@s.LoggedUserInheritedServicesAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                      response_schemas=s.LoggedUserServices_GET_responses)
@view_config(route_name=s.UserInheritedServicesAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_inherited_services_view(request):
    """[DEPRECATED: use '/users/{user_name}/services?inherit=true']
    List all services a user has permissions on with his inherited user and groups permissions."""
    LOGGER.warning("Route deprecated: [{0}], Instead Use: [{1}]"
                   .format(s.LoggedUserInheritedServicesAPI.path, s.LoggedUserServicesAPI.path + "?inherit=true"))
    return HTTPMovedPermanently(location=request.path.replace("/inherited_services", "/services?inherit=true"))


@s.UserServiceInheritedPermissionsAPI.get(schema=s.UserServicePermissions_GET_RequestSchema,
                                          tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                          response_schemas=s.UserServicePermissions_GET_responses)
@s.LoggedUserServiceInheritedPermissionsAPI.get(schema=s.UserServicePermissions_GET_RequestSchema,
                                                tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                                response_schemas=s.LoggedUserServicePermissions_GET_responses)
@view_config(route_name=s.UserServiceInheritedPermissionsAPI.name, request_method="GET",
             permission=NO_PERMISSION_REQUIRED)
def get_user_service_inherited_permissions_view(request):
    """[DEPRECATED: use '/users/{user_name}/services/{service_name}/permissions?inherit=true']
    List all permissions a user has on a service using all his inherited user and groups permissions."""
    LOGGER.warning("Route deprecated: [{0}], Instead Use: [{1}]"
                   .format(s.UserServiceInheritedPermissionsAPI.path,
                           s.UserServicePermissionsAPI.path + "?inherit=true"))
    return HTTPMovedPermanently(location=request.path.replace("/inherited_permissions", "/permissions?inherit=true"))


@s.UserServicePermissionsAPI.get(schema=s.UserServicePermissions_GET_RequestSchema,
                                 tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                 response_schemas=s.UserServicePermissions_GET_responses)
@s.LoggedUserServicePermissionsAPI.get(schema=s.UserServicePermissions_GET_RequestSchema,
                                       tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                       response_schemas=s.LoggedUserServicePermissions_GET_responses)
@view_config(route_name=s.UserServicePermissionsAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_service_permissions_view(request):
    """
    List all permissions a user has on a service.
    """
    user = ar.get_user_matchdict_checked_or_logged(request)
    service = ar.get_service_matchdict_checked(request)
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit"))
    perms = ax.evaluate_call(lambda: uu.get_user_service_permissions(service=service, user=user, request=request,
                                                                     inherit_groups_permissions=inherit_groups_perms),
                             fallback=lambda: request.db.rollback(), http_error=HTTPNotFound,
                             msg_on_fail=s.UserServicePermissions_GET_NotFoundResponseSchema.description,
                             content={u"service_name": str(service.resource_name), u"user_name": str(user.user_name)})
    return ax.valid_http(http_success=HTTPOk, detail=s.UserServicePermissions_GET_OkResponseSchema.description,
                         content={u"permission_names": sorted(p.value for p in perms)})


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
    permission = ar.get_permission_multiformat_post_checked(request, service)
    return uu.create_user_resource_permission_response(user, service, permission, request.db)


@s.UserServicePermissionAPI.delete(schema=s.UserServicePermission_DELETE_RequestSchema, tags=[s.UsersTag],
                                   response_schemas=s.UserServicePermission_DELETE_responses)
@s.LoggedUserServicePermissionAPI.delete(schema=s.UserServicePermission_DELETE_RequestSchema, tags=[s.LoggedUserTag],
                                         response_schemas=s.LoggedUserServicePermission_DELETE_responses)
@view_config(route_name=s.UserServicePermissionAPI.name, request_method="DELETE")
def delete_user_service_permission_view(request):
    """
    Delete a direct permission on a service for a user (not including his groups permissions).
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
@view_config(route_name=s.UserServiceResourcesAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_user_service_resources_view(request):
    """
    List all resources under a service a user has permission on.
    """
    inherit_groups_perms = asbool(ar.get_query_param(request, "inherit"))
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
    return ax.valid_http(http_success=HTTPOk, detail=s.UserServiceResources_GET_OkResponseSchema.description,
                         content={u"service": user_svc_res_json})


@s.UserServiceInheritedResourcesAPI.get(tags=[s.UsersTag], api_security=s.SecurityEveryoneAPI,
                                        response_schemas=s.UserServiceResources_GET_responses)
@s.LoggedUserServiceInheritedResourcesAPI.get(tags=[s.LoggedUserTag], api_security=s.SecurityEveryoneAPI,
                                              response_schemas=s.LoggedUserServiceResources_GET_responses)
@view_config(route_name=s.UserServiceInheritedResourcesAPI.name, request_method="GET",
             permission=NO_PERMISSION_REQUIRED)
def get_user_service_inherited_resources_view(request):
    """[DEPRECATED: use '/users/{user_name}/services/{service_name}/resources?inherit=true']
    List all resources under a service a user has permission on using all his inherited user and groups permissions."""
    LOGGER.warning("Route deprecated: [{0}], Instead Use: [{1}]"
                   .format(s.UserServiceInheritedResourcesAPI.path, s.UserServiceResourcesAPI.path + "?inherit=true"))
    return HTTPMovedPermanently(location=request.path.replace("/inherited_resources", "/resources?inherit=true"))
