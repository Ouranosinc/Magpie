from magpie.definitions.pyramid_definitions import *
from magpie.definitions.ziggurat_definitions import *
from magpie.api.api_requests import *
from magpie.api.api_rest_schemas import *
from magpie.api.management.user.user_formats import *
from magpie.api.management.user.user_utils import *
from magpie.api.management.group.group_utils import *
from magpie.api.management.service.service_utils import get_services_by_type
from magpie.api.management.service.service_formats import format_service, format_service_resources
from magpie.common import str2bool
import logging
LOGGER = logging.getLogger(__name__)


@UsersAPI.get(tags=[UsersTag], response_schemas=Users_GET_responses)
@view_config(route_name=UsersAPI.name, request_method='GET')
def get_users(request):
    """List all registered user names."""
    user_name_list = evaluate_call(lambda: [user.user_name for user in models.User.all(db_session=request.db)],
                                   fallback=lambda: request.db.rollback(),
                                   httpError=HTTPForbidden, msgOnFail=Users_GET_ForbiddenResponseSchema.description)
    return valid_http(httpSuccess=HTTPOk, content={u'user_names': sorted(user_name_list)},
                      detail=Users_GET_OkResponseSchema.description)


@UsersAPI.post(schema=Users_POST_RequestSchema(), tags=[UsersTag], response_schemas=Users_POST_responses)
@view_config(route_name=UsersAPI.name, request_method='POST')
def create_user_view(request):
    """Create a new user."""
    user_name = get_multiformat_post(request, 'user_name')
    email = get_multiformat_post(request, 'email')
    password = get_multiformat_post(request, 'password')
    group_name = get_multiformat_post(request, 'group_name')
    check_user_info(user_name, email, password, group_name)
    return create_user(user_name, password, email, group_name, db_session=request.db)


@UserAPI.put(schema=User_PUT_RequestSchema(), tags=[UsersTag], response_schemas=User_PUT_responses)
@LoggedUserAPI.put(schema=User_PUT_RequestSchema(), tags=[LoggedUserTag], response_schemas=LoggedUser_PUT_responses)
@view_config(route_name=UserAPI.name, request_method='PUT')
def update_user_view(request):
    """Update user information by user name."""
    user = get_user_matchdict_checked(request, user_name_key='user_name')
    new_user_name = get_multiformat_post(request, 'user_name')
    new_email = get_multiformat_post(request, 'email')
    new_password = get_multiformat_post(request, 'password')
    new_password = user.user_password if new_password is None else new_password
    check_user_info(new_user_name, new_email, new_password, group_name=new_user_name)

    if user.user_name != new_user_name:
        evaluate_call(lambda: models.User.by_user_name(new_user_name, db_session=request.db),
                      fallback=lambda: request.db.rollback(),
                      httpError=HTTPConflict, msgOnFail=User_PUT_ConflictResponseSchema.description)
        user.user_name = new_user_name
    if user.email != new_email:
        user.email = new_email
    if user.user_password != new_password and new_password is not None:
        user.set_password(new_password)
        user.regenerate_security_code()

    return valid_http(httpSuccess=HTTPOk, detail=Users_PUT_OkResponseSchema.description)


@UserAPI.get(tags=[UsersTag], api_security=SecurityEveryoneAPI, response_schemas=User_GET_responses)
@LoggedUserAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI, response_schemas=LoggedUser_GET_responses)
@view_config(route_name=UserAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_view(request):
    """Get user information by name."""
    user = get_user_matchdict_checked_or_logged(request)
    return valid_http(httpSuccess=HTTPOk, detail=User_GET_OkResponseSchema.description,
                      content={u'user': format_user(user)})


@UserAPI.delete(schema=User_DELETE_RequestSchema(), tags=[UsersTag], response_schemas=User_DELETE_responses)
@LoggedUserAPI.delete(schema=User_DELETE_RequestSchema(), tags=[LoggedUserTag],
                      response_schemas=LoggedUser_DELETE_responses)
@view_config(route_name=UserAPI.name, request_method='DELETE')
def delete_user(request):
    """Delete a user by name."""
    user = get_user_matchdict_checked_or_logged(request)
    db = request.db
    evaluate_call(lambda: db.delete(user), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail=User_DELETE_ForbiddenResponseSchema.description)
    return valid_http(httpSuccess=HTTPOk, detail=User_DELETE_OkResponseSchema.description)


@UserGroupsAPI.get(tags=[UsersTag], api_security=SecurityEveryoneAPI, response_schemas=UserGroups_GET_responses)
@LoggedUserGroupsAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                         response_schemas=LoggedUserGroups_GET_responses)
@view_config(route_name=UserGroupsAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_groups(request):
    """List all groups a user belongs to."""
    user = get_user_matchdict_checked_or_logged(request)
    group_names = get_user_groups_checked(request, user)
    return valid_http(httpSuccess=HTTPOk, detail=UserGroups_GET_OkResponseSchema.description,
                      content={u'group_names': group_names})


@UserGroupsAPI.post(schema=UserGroups_POST_RequestSchema(), tags=[UsersTag], response_schemas=UserGroups_POST_responses)
@LoggedUserGroupsAPI.post(schema=UserGroups_POST_RequestSchema(), tags=[LoggedUserTag],
                          response_schemas=LoggedUserGroups_POST_responses)
@view_config(route_name=UserGroupsAPI.name, request_method='POST')
def assign_user_group(request):
    """Assign a user to a group."""
    db = request.db
    user = get_user_matchdict_checked_or_logged(request)

    group_name = get_value_multiformat_post_checked(request, 'group_name')
    group = evaluate_call(lambda: zig.GroupService.by_group_name(group_name, db_session=request.db),
                          fallback=lambda: request.db.rollback(),
                          httpError=HTTPForbidden, msgOnFail=UserGroups_POST_ForbiddenResponseSchema.description)
    verify_param(group, notNone=True, httpError=HTTPNotFound,
                 msgOnFail=UserGroups_POST_GroupNotFoundResponseSchema.description)

    new_user_group = models.UserGroup(group_id=group.id, user_id=user.id)

    evaluate_call(lambda: db.add(new_user_group), fallback=lambda: db.rollback(),
                  httpError=HTTPConflict, msgOnFail=UserGroups_POST_ConflictResponseSchema.description,
                  content={u'user_name': user.user_name, u'group_name': group.group_name})
    return valid_http(httpSuccess=HTTPCreated, detail=UserGroups_POST_CreatedResponseSchema.description)


@UserGroupAPI.delete(schema=UserGroup_DELETE_RequestSchema(), tags=[UsersTag],
                     response_schemas=UserGroup_DELETE_responses)
@LoggedUserGroupAPI.delete(schema=UserGroup_DELETE_RequestSchema(), tags=[LoggedUserTag],
                           response_schemas=LoggedUserGroup_DELETE_responses)
@view_config(route_name=UserGroupAPI.name, request_method='DELETE')
def delete_user_group(request):
    """Remove a user from a group."""
    db = request.db
    user = get_user_matchdict_checked_or_logged(request)
    group = get_group_matchdict_checked(request)

    def del_usr_grp(usr, grp):
        db.query(models.UserGroup) \
            .filter(models.UserGroup.user_id == usr.id) \
            .filter(models.UserGroup.group_id == grp.id) \
            .delete()

    evaluate_call(lambda: del_usr_grp(user, group), fallback=lambda: db.rollback(),
                  httpError=HTTPNotFound, msgOnFail=UserGroup_DELETE_NotFoundResponseSchema.description,
                  content={u'user_name': user.user_name, u'group_name': group.group_name})
    return valid_http(httpSuccess=HTTPOk, detail=UserGroup_DELETE_OkResponseSchema.description)


def get_user_resources_runner(request, inherited_group_resources_permissions=True):
    user = get_user_matchdict_checked_or_logged(request)
    inherit_perms = inherited_group_resources_permissions
    db = request.db

    def build_json_user_resource_tree(usr):
        json_res = {}
        for svc in models.Service.all(db_session=db):
            svc_perms = get_user_service_permissions(user=usr, service=svc, db_session=db,
                                                     inherit_groups_permissions=inherit_perms)
            if svc.type not in json_res:
                json_res[svc.type] = {}
            res_perms_dict = get_user_service_resources_permissions_dict(user=usr, service=svc, db_session=db,
                                                                         inherit_groups_permissions=inherit_perms)
            json_res[svc.type][svc.resource_name] = format_service_resources(
                svc,
                db_session=db,
                service_perms=svc_perms,
                resources_perms_dict=res_perms_dict,
                display_all=False,
                show_private_url=False,
            )
        return json_res

    usr_res_dict = evaluate_call(lambda: build_json_user_resource_tree(user),
                                 fallback=lambda: db.rollback(), httpError=HTTPNotFound,
                                 msgOnFail=UserResources_GET_NotFoundResponseSchema.description,
                                 content={u'user_name': user.user_name, u'resource_types': [u'service']})
    return valid_http(httpSuccess=HTTPOk, detail=UserResources_GET_OkResponseSchema.description,
                      content={u'resources': usr_res_dict})


@UserResourcesAPI.get(tags=[UsersTag], api_security=SecurityEveryoneAPI, response_schemas=UserResources_GET_responses)
@LoggedUserResourcesAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                            response_schemas=LoggedUserResources_GET_responses)
@view_config(route_name=UserResourcesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_resources_view(request):
    """List all resources a user has direct permission on (not including his groups permissions)."""
    inherit_groups_perms = str2bool(get_query_param(request, 'inherit'))
    return get_user_resources_runner(request, inherited_group_resources_permissions=inherit_groups_perms)


@UserInheritedResourcesAPI.get(tags=[UsersTag], api_security=SecurityEveryoneAPI,
                               response_schemas=UserResources_GET_responses)
@LoggedUserInheritedResourcesAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                                     response_schemas=LoggedUserResources_GET_responses)
@view_config(route_name=UserInheritedResourcesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_inherited_resources_view(request):
    """List all resources a user has permission on with his inherited user and groups permissions."""
    LOGGER.warn("Route deprecated: [{0}], Instead Use: [{1}]"
                .format(UserInheritedResourcesAPI.path, UserResourcesAPI.path + "?inherit=true"))
    return get_user_resources_runner(request, inherited_group_resources_permissions=True)


@UserResourcePermissionsAPI.get(tags=[UsersTag], api_security=SecurityEveryoneAPI,
                                response_schemas=UserResourcePermissions_GET_responses)
@LoggedUserResourcePermissionsAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                                      response_schemas=LoggedUserResourcePermissions_GET_responses)
@view_config(route_name=UserResourcePermissionsAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_resource_permissions_view(request):
    """List all direct permissions a user has on a specific resource (not including his groups permissions)."""
    user = get_user_matchdict_checked_or_logged(request)
    resource = get_resource_matchdict_checked(request, 'resource_id')
    inherit_groups_perms = str2bool(get_query_param(request, 'inherit'))
    perm_names = get_user_resource_permissions(resource=resource, user=user, db_session=request.db,
                                               inherit_groups_permissions=inherit_groups_perms)
    return valid_http(httpSuccess=HTTPOk, detail=UserResourcePermissions_GET_OkResponseSchema.description,
                      content={u'permission_names': sorted(perm_names)})


@UserResourceInheritedPermissionsAPI.get(tags=[UsersTag], api_security=SecurityEveryoneAPI,
                                         response_schemas=UserResourcePermissions_GET_responses)
@LoggedUserResourceInheritedPermissionsAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                                               response_schemas=LoggedUserResourcePermissions_GET_responses)
@view_config(route_name=UserResourceInheritedPermissionsAPI.name, request_method='GET',
             permission=NO_PERMISSION_REQUIRED)
def get_user_resource_inherit_groups_permissions_view(request):
    """List all permissions a user has on a specific resource with his inherited user and groups permissions."""
    LOGGER.warn("Route deprecated: [{0}], Instead Use: [{1}]"
                .format(UserResourceInheritedPermissionsAPI.path, UserResourcePermissionsAPI.path + "?inherit=true"))

    user = get_user_matchdict_checked_or_logged(request)
    resource = get_resource_matchdict_checked(request, 'resource_id')
    perm_names = get_user_resource_permissions(resource=resource, user=user, db_session=request.db,
                                               inherit_groups_permissions=True)
    return valid_http(httpSuccess=HTTPOk, detail=UserResourcePermissions_GET_OkResponseSchema.description,
                      content={u'permission_names': sorted(perm_names)})


@UserResourcePermissionsAPI.post(schema=UserResourcePermissions_POST_RequestSchema(), tags=[UsersTag],
                                 response_schemas=UserResourcePermissions_POST_responses)
@LoggedUserResourcePermissionsAPI.post(schema=UserResourcePermissions_POST_RequestSchema(), tags=[LoggedUserTag],
                                       response_schemas=LoggedUserResourcePermissions_POST_responses)
@view_config(route_name=UserResourcePermissionsAPI.name, request_method='POST')
def create_user_resource_permission_view(request):
    """Create a permission on specific resource for a user."""
    user = get_user_matchdict_checked_or_logged(request)
    resource = get_resource_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, resource)
    return create_user_resource_permission(perm_name, resource, user.id, request.db)


@UserResourcePermissionAPI.delete(schema=UserResourcePermission_DELETE_RequestSchema(), tags=[UsersTag],
                                  response_schemas=UserResourcePermission_DELETE_responses)
@LoggedUserResourcePermissionAPI.delete(schema=UserResourcePermission_DELETE_RequestSchema(), tags=[LoggedUserTag],
                                        response_schemas=LoggedUserResourcePermission_DELETE_responses)
@view_config(route_name=UserResourcePermissionAPI.name, request_method='DELETE')
def delete_user_resource_permission_view(request):
    """Delete a permission on a resource for a user (not including his groups permissions)."""
    user = get_user_matchdict_checked_or_logged(request)
    resource = get_resource_matchdict_checked(request)
    perm_name = get_permission_matchdict_checked(request, resource)
    return delete_user_resource_permission(perm_name, resource, user.id, request.db)


@UserServicesAPI.get(tags=[UsersTag], schema=UserServices_GET_RequestSchema,
                     api_security=SecurityEveryoneAPI, response_schemas=UserServices_GET_responses)
@LoggedUserServicesAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                           response_schemas=LoggedUserServices_GET_responses)
@view_config(route_name=UserServicesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_services_view(request):
    """List all services a user has permission on."""
    user = get_user_matchdict_checked_or_logged(request)
    cascade_resources = str2bool(get_query_param(request, 'cascade'))
    inherit_groups_perms = str2bool(get_query_param(request, 'inherit'))
    format_as_list = str2bool(get_query_param(request, 'list'))

    svc_json = get_user_services(user, db_session=request.db,
                                 cascade_resources=cascade_resources,
                                 inherit_groups_permissions=inherit_groups_perms,
                                 format_as_list=format_as_list)
    return valid_http(httpSuccess=HTTPOk, detail=UserServices_GET_OkResponseSchema.description,
                      content={u'services': svc_json})


@UserInheritedServicesAPI.get(tags=[UsersTag], api_security=SecurityEveryoneAPI,
                              response_schemas=UserServices_GET_responses)
@LoggedUserInheritedServicesAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                                    response_schemas=LoggedUserServices_GET_responses)
@view_config(route_name=UserInheritedServicesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_inherited_services_view(request):
    """List all services a user has permission on with his inherited user and groups permissions."""
    LOGGER.warn("Route deprecated: [{0}], Instead Use: [{1}]"
                .format(LoggedUserInheritedServicesAPI.path, LoggedUserServicesAPI.path + "?inherit=true"))
    user = get_user_matchdict_checked_or_logged(request)
    svc_json = get_user_services(user, db_session=request.db, cascade_resources=False, inherit_groups_permissions=True)
    return valid_http(httpSuccess=HTTPOk, detail=UserServices_GET_OkResponseSchema.description,
                      content={u'services': svc_json})


@UserServiceInheritedPermissionsAPI.get(schema=UserServicePermissions_GET_RequestSchema,
                                        tags=[UsersTag], api_security=SecurityEveryoneAPI,
                                        response_schemas=UserServicePermissions_GET_responses)
@LoggedUserServiceInheritedPermissionsAPI.get(schema=UserServicePermissions_GET_RequestSchema,
                                              tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                                              response_schemas=LoggedUserServicePermissions_GET_responses)
@view_config(route_name=UserServiceInheritedPermissionsAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_service_inherited_permissions_view(request):
    """List all permissions a user has on a service using all his inherited user and groups permissions."""
    LOGGER.warn("Route deprecated: [{0}], Instead Use: [{1}]"
                .format(UserServiceInheritedPermissionsAPI.path, UserServicePermissionsAPI.path + "?inherit=true"))
    user = get_user_matchdict_checked_or_logged(request)
    service = get_service_matchdict_checked(request)
    perms = evaluate_call(lambda: get_user_service_permissions(service=service, user=user, db_session=request.db,
                                                               inherit_groups_permissions=True),
                          fallback=lambda: request.db.rollback(), httpError=HTTPNotFound,
                          msgOnFail=UserServicePermissions_GET_NotFoundResponseSchema.description,
                          content={u'service_name': str(service.resource_name), u'user_name': str(user.user_name)})
    return valid_http(httpSuccess=HTTPOk, detail=UserServicePermissions_GET_OkResponseSchema.description,
                      content={u'permission_names': sorted(perms)})


@UserServicePermissionsAPI.get(schema=UserServicePermissions_GET_RequestSchema,
                               tags=[UsersTag], api_security=SecurityEveryoneAPI,
                               response_schemas=UserServicePermissions_GET_responses)
@LoggedUserServicePermissionsAPI.get(schema=UserServicePermissions_GET_RequestSchema,
                                     tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                                     response_schemas=LoggedUserServicePermissions_GET_responses)
@view_config(route_name=UserServicePermissionsAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_service_permissions_view(request):
    """List all permissions a user has on a service."""
    user = get_user_matchdict_checked_or_logged(request)
    service = get_service_matchdict_checked(request)
    inherit_groups_perms = str2bool(get_query_param(request, 'inherit'))
    perms = evaluate_call(lambda: get_user_service_permissions(service=service, user=user, db_session=request.db,
                                                               inherit_groups_permissions=inherit_groups_perms),
                          fallback=lambda: request.db.rollback(), httpError=HTTPNotFound,
                          msgOnFail=UserServicePermissions_GET_NotFoundResponseSchema.description,
                          content={u'service_name': str(service.resource_name), u'user_name': str(user.user_name)})
    return valid_http(httpSuccess=HTTPOk, detail=UserServicePermissions_GET_OkResponseSchema.description,
                      content={u'permission_names': sorted(perms)})


@UserServicePermissionsAPI.post(schema=UserServicePermissions_POST_RequestSchema, tags=[UsersTag],
                                response_schemas=UserServicePermissions_POST_responses)
@LoggedUserServicePermissionsAPI.post(schema=UserServicePermissions_POST_RequestSchema, tags=[LoggedUserTag],
                                      response_schemas=LoggedUserServicePermissions_POST_responses)
@view_config(route_name=UserServicePermissionsAPI.name, request_method='POST')
def create_user_service_permission(request):
    """Create a permission on a service for a user."""
    user = get_user_matchdict_checked_or_logged(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, service)
    return create_user_resource_permission(perm_name, service, user.id, request.db)


@UserServicePermissionAPI.delete(schema=UserServicePermission_DELETE_RequestSchema, tags=[UsersTag],
                                 response_schemas=UserServicePermission_DELETE_responses)
@LoggedUserServicePermissionAPI.delete(schema=UserServicePermission_DELETE_RequestSchema, tags=[LoggedUserTag],
                                       response_schemas=LoggedUserServicePermission_DELETE_responses)
@view_config(route_name=UserServicePermissionAPI.name, request_method='DELETE')
def delete_user_service_permission(request):
    """Delete a direct permission on a service for a user (not including his groups permissions)."""
    user = get_user_matchdict_checked_or_logged(request)
    service = get_service_matchdict_checked(request)
    perm_name = get_permission_multiformat_post_checked(request, service)
    return delete_user_resource_permission(perm_name, service, user.id, request.db)


def get_user_service_resource_permissions_runner(request, inherit_groups_permissions):
    """
    Resource permissions a user as on a specific service

    :param request:
    :param inherit_groups_permissions:
        only direct permissions if False, otherwise resolve permissions with user and his groups.
    :return:
    """
    user = get_user_matchdict_checked_or_logged(request)
    service = get_service_matchdict_checked(request)
    service_perms = get_user_service_permissions(
        user, service, db_session=request.db, inherit_groups_permissions=inherit_groups_permissions)
    resources_perms_dict = get_user_service_resources_permissions_dict(
        user, service, db_session=request.db, inherit_groups_permissions=inherit_groups_permissions)
    user_svc_res_json = format_service_resources(
        service=service,
        db_session=request.db,
        service_perms=service_perms,
        resources_perms_dict=resources_perms_dict,
        display_all=False,
        show_private_url=False,
    )
    return valid_http(httpSuccess=HTTPOk, detail=UserServiceResources_GET_OkResponseSchema.description,
                      content={u'service': user_svc_res_json})


@UserServiceResourcesAPI.get(schema=UserServiceResources_GET_RequestSchema,
                             tags=[UsersTag], api_security=SecurityEveryoneAPI,
                             response_schemas=UserServiceResources_GET_responses)
@LoggedUserServiceResourcesAPI.get(schema=UserServiceResources_GET_RequestSchema,
                                   tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                                   response_schemas=LoggedUserServiceResources_GET_responses)
@view_config(route_name=UserServiceResourcesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_service_resources_view(request):
    """List all resources under a service a user has permission on."""
    inherit_groups_perms = str2bool(get_query_param(request, 'inherit'))
    return get_user_service_resource_permissions_runner(request, inherit_groups_permissions=inherit_groups_perms)


@UserServiceInheritedResourcesAPI.get(tags=[UsersTag], api_security=SecurityEveryoneAPI,
                                      response_schemas=UserServiceResources_GET_responses)
@LoggedUserServiceInheritedResourcesAPI.get(tags=[LoggedUserTag], api_security=SecurityEveryoneAPI,
                                            response_schemas=LoggedUserServiceResources_GET_responses)
@view_config(route_name=UserServiceInheritedResourcesAPI.name, request_method='GET', permission=NO_PERMISSION_REQUIRED)
def get_user_service_inherited_resources_view(request):
    """List all resources under a service a user has permission on using all his inherited user and groups
    permissions."""
    LOGGER.warn("Route deprecated: [{0}], Instead Use: [{1}]"
                .format(UserServiceInheritedResourcesAPI.path, UserServiceResourcesAPI.path + "?inherit=true"))
    return get_user_service_resource_permissions_runner(request, inherit_groups_permissions=True)
