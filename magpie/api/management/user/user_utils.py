from magpie.api.api_except import *
from magpie.api.api_rest_schemas import *
from magpie.api.management.service.service_formats import format_service
from magpie.api.management.resource.resource_utils import check_valid_service_resource_permission
from magpie.api.management.user.user_formats import *
from magpie.definitions.ziggurat_definitions import *
from magpie.services import service_type_dict
from magpie import models


def create_user(user_name, password, email, group_name, db_session):
    db = db_session

    # Check that group already exists
    group_check = evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=db),
                                httpError=HTTPForbidden, msgOnFail=UserGroup_GET_ForbiddenResponseSchema.description)
    verify_param(group_check, notNone=True, httpError=HTTPNotAcceptable,
                 msgOnFail=UserGroup_Check_ForbiddenResponseSchema.description)

    # Check if user already exists
    user_check = evaluate_call(lambda: UserService.by_user_name(user_name=user_name, db_session=db),
                               httpError=HTTPForbidden, msgOnFail=User_Check_ForbiddenResponseSchema.description)
    verify_param(user_check, isNone=True, httpError=HTTPConflict,
                 msgOnFail=User_Check_ConflictResponseSchema.description)

    # Create user with specified name and group to assign
    user_model = models.User(user_name=user_name, email=email)
    if password:
        user_model.set_password(password)
        user_model.regenerate_security_code()
    evaluate_call(lambda: db.add(user_model), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail=Users_POST_ForbiddenResponseSchema.description)

    # Assign user to default group and own group
    new_user = evaluate_call(lambda: UserService.by_user_name(user_name, db_session=db),
                             httpError=HTTPForbidden, msgOnFail=UserNew_POST_ForbiddenResponseSchema.description)
    group_entry = models.UserGroup(group_id=group_check.id, user_id=new_user.id)
    evaluate_call(lambda: db.add(group_entry), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail=UserGroup_GET_ForbiddenResponseSchema.description)

    return valid_http(httpSuccess=HTTPCreated, detail=Users_POST_CreatedResponseSchema.description,
                      content={u'user': format_user(new_user, [group_name])})


def create_user_resource_permission(permission_name, resource, user_id, db_session):
    check_valid_service_resource_permission(permission_name, resource, db_session)
    resource_id = resource.resource_id
    new_perm = models.UserResourcePermission(resource_id=resource_id, user_id=user_id)
    verify_param(new_perm, notNone=True, httpError=HTTPNotAcceptable, paramName=u'permission_name',
                 content={u'resource_id': resource_id, u'user_id': user_id},
                 msgOnFail=UserResourcePermissions_POST_NotAcceptableResponseSchema.description)
    new_perm.perm_name = permission_name
    evaluate_call(lambda: db_session.add(new_perm), fallback=lambda: db_session.rollback(),
                  httpError=HTTPConflict, msgOnFail=UserResourcePermissions_POST_ConflictResponseSchema.description,
                  content={u'resource_id': resource_id, u'user_id': user_id, u'permission_name': permission_name})
    return valid_http(httpSuccess=HTTPCreated, detail=UserResourcePermissions_POST_CreatedResponseSchema.description,
                      content={u'resource_id': resource_id, u'user_id': user_id, u'permission_name': permission_name})


def delete_user_resource_permission(permission_name, resource, user_id, db_session):
    check_valid_service_resource_permission(permission_name, resource, db_session)
    resource_id = resource.resource_id
    del_perm = UserResourcePermissionService.get(user_id, resource_id, permission_name, db_session)
    evaluate_call(lambda: db_session.delete(del_perm), fallback=lambda: db_session.rollback(),
                  httpError=HTTPNotFound, msgOnFail=UserResourcePermissions_DELETE_NotFoundResponseSchema.description,
                  content={u'resource_id': resource_id, u'user_id': user_id, u'permission_name': permission_name})
    return valid_http(httpSuccess=HTTPOk, detail=UserResourcePermissions_DELETE_OkResponseSchema.description)


def filter_user_permission(resource_permission_tuple_list, user):
    return filter(lambda perm: perm.group is None and perm.type == u'user' and perm.user.user_name == user.user_name,
                  resource_permission_tuple_list)


def get_user_resource_permissions(user, resource, db_session, inherit_groups_permissions=True):
    if resource.owner_user_id == user.id:
        permission_names = models.resource_type_dict[resource.type].permission_names
    else:
        res_perm_tuple_list = resource.perms_for_user(user, db_session=db_session)
        if not inherit_groups_permissions:
            res_perm_tuple_list = filter_user_permission(res_perm_tuple_list, user)
        permission_names = [permission.perm_name for permission in res_perm_tuple_list]
    return sorted(set(permission_names))  # remove any duplicates that could be incorporated by multiple groups


def get_user_services(user, db_session, cascade_resources=False,
                      inherit_groups_permissions=False, format_as_list=False):
    """
    Returns services by type with corresponding services by name containing sub-dict information.

    :param user: user for which to find services
    :param db_session: database session connection
    :param cascade_resources:
        If `False`, return only services with *Direct* user permissions on their corresponding service-resource.
        Otherwise, return every service that has at least one sub-resource with user permissions.
    :param inherit_groups_permissions:
        If `False`, return only user-specific service/sub-resources permissions.
        Otherwise, resolve inherited permissions using all groups the user is member of.
    :param format_as_list:
        returns as list of service dict information (not grouped by type and by name)
    :return: only services which the user as *Direct* or *Inherited* permissions, according to `inherit_from_resources`
    :rtype:
        dict of services by type with corresponding services by name containing sub-dict information,
        unless `format_as_dict` is `True`
    """
    resource_type = None if cascade_resources else ['service']
    res_perm_dict = get_user_resources_permissions_dict(user, resource_types=resource_type, db_session=db_session,
                                                        inherit_groups_permissions=inherit_groups_permissions)

    services = {}
    for resource_id, perms in res_perm_dict.items():
        svc = models.Service.by_resource_id(resource_id=resource_id, db_session=db_session)
        if svc.resource_type != 'service' and cascade_resources:
            svc = models.Service.by_resource_id(resource_id=svc.root_service_id, db_session=db_session)
            perms = service_type_dict[svc.type].permission_names
        if svc.type not in services:
            services[svc.type] = {}
        if svc.resource_name not in services[svc.type]:
            services[svc.type][svc.resource_name] = format_service(svc, perms, show_private_url=False)

    if not format_as_list:
        return services

    services_list = list()
    for svc_type in services:
        for svc_name in services[svc_type]:
            services_list.append(services[svc_type][svc_name])
    return services_list


def get_user_service_permissions(user, service, db_session, inherit_groups_permissions=True):
    if service.owner_user_id == user.id:
        permission_names = service_type_dict[service.type].permission_names
    else:
        svc_perm_tuple_list = service.perms_for_user(user, db_session=db_session)
        if not inherit_groups_permissions:
            svc_perm_tuple_list = filter_user_permission(svc_perm_tuple_list, user)
        permission_names = [permission.perm_name for permission in svc_perm_tuple_list]
    return sorted(set(permission_names))  # remove any duplicates that could be incorporated by multiple groups


def get_user_resources_permissions_dict(user, db_session, resource_types=None,
                                        resource_ids=None, inherit_groups_permissions=True):
    """
    Creates a dictionary of resources by id with corresponding permissions of the user.

    :param user: user for which to find services
    :param db_session: database session connection
    :param resource_types: (list) filter the search query with specified resource types
    :param resource_ids: (list) filter the search query with specified resource ids
    :param inherit_groups_permissions:
        If `False`, return only user-specific resource permissions.
        Otherwise, resolve inherited permissions using all groups the user is member of.
    :return: only services which the user as *Direct* or *Inherited* permissions, according to `inherit_from_resources`
    """
    verify_param(user, notNone=True, httpError=HTTPNotFound,
                 msgOnFail=UserResourcePermissions_GET_NotFoundResponseSchema.description)
    res_perm_tuple_list = user.resources_with_possible_perms(resource_ids=resource_ids,
                                                             resource_types=resource_types, db_session=db_session)
    if not inherit_groups_permissions:
        res_perm_tuple_list = filter_user_permission(res_perm_tuple_list, user)
    resources_permissions_dict = {}
    for res_perm in res_perm_tuple_list:
        if res_perm.resource.resource_id not in resources_permissions_dict:
            resources_permissions_dict[res_perm.resource.resource_id] = [res_perm.perm_name]
        else:
            resources_permissions_dict[res_perm.resource.resource_id].append(res_perm.perm_name)

    # remove any duplicates that could be incorporated by multiple groups
    for res_id in resources_permissions_dict:
        resources_permissions_dict[res_id] = sorted(set(resources_permissions_dict[res_id]))

    return resources_permissions_dict


def get_user_service_resources_permissions_dict(user, service, db_session, inherit_groups_permissions=True):
    resources_under_service = models.resource_tree_service.from_parent_deeper(parent_id=service.resource_id,
                                                                              db_session=db_session)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    return get_user_resources_permissions_dict(user, db_session, resource_types=None, resource_ids=resource_ids,
                                               inherit_groups_permissions=inherit_groups_permissions)


def check_user_info(user_name, email, password, group_name):
    verify_param(user_name, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 paramName=u'user_name', msgOnFail=Users_CheckInfo_Name_BadRequestResponseSchema.description)
    verify_param(len(user_name), isIn=True, httpError=HTTPBadRequest,
                 paramName=u'user_name', paramCompare=range(1, 1 + MAGPIE_USER_NAME_MAX_LENGTH),
                 msgOnFail=Users_CheckInfo_Size_BadRequestResponseSchema.description)
    verify_param(email, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 paramName=u'email', msgOnFail=Users_CheckInfo_Email_BadRequestResponseSchema.description)
    verify_param(password, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 paramName=u'password', msgOnFail=Users_CheckInfo_Password_BadRequestResponseSchema.description)
    verify_param(group_name, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 paramName=u'group_name', msgOnFail=Users_CheckInfo_GroupName_BadRequestResponseSchema.description)
    verify_param(user_name, paramCompare=[MAGPIE_LOGGED_USER], notIn=True, httpError=HTTPConflict,
                 paramName=u'user_name', msgOnFail=Users_CheckInfo_Login_ConflictResponseSchema.description)


def get_user_groups_checked(request, user):
    verify_param(user, notNone=True, httpError=HTTPNotFound,
                 msgOnFail=Groups_CheckInfo_NotFoundResponseSchema.description)
    db = request.db
    group_names = evaluate_call(lambda: [group.group_name for group in user.groups], fallback=lambda: db.rollback(),
                                httpError=HTTPForbidden, msgOnFail=Groups_CheckInfo_ForbiddenResponseSchema.description)
    return sorted(group_names)
