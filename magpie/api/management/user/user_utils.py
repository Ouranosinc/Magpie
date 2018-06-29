from magpie import *
from api.api_except import *
from api.management.resource.resource_utils import check_valid_service_resource_permission
from definitions.ziggurat_definitions import *
from services import service_type_dict
import models


def create_user(user_name, password, email, group_name, db_session):
    db = db_session

    # Check that group already exists
    group_check = evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=db),
                                httpError=HTTPForbidden, msgOnFail="Group query was refused by db")
    verify_param(group_check, notNone=True, httpError=HTTPNotAcceptable, msgOnFail="Group for new user doesn't exist")

    # Check if user already exists
    user_check = evaluate_call(lambda: UserService.by_user_name(user_name=user_name, db_session=db),
                               httpError=HTTPForbidden, msgOnFail="User check query was refused by db")
    verify_param(user_check, isNone=True, httpError=HTTPConflict,
                 msgOnFail="User name matches an already existing user name")

    # Create user with specified name and group to assign
    user_model = models.User(user_name=user_name, email=email)
    if password:
        user_model.set_password(password)
        user_model.regenerate_security_code()
    evaluate_call(lambda: db.add(user_model), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Failed to add user to db")

    # Assign user to default group and own group
    new_user = evaluate_call(lambda: UserService.by_user_name(user_name, db_session=db),
                             httpError=HTTPForbidden, msgOnFail="New user query was refused by db")
    group_entry = models.UserGroup(group_id=group_check.id, user_id=new_user.id)
    evaluate_call(lambda: db.add(group_entry), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Failed to add user-group to db")

    return valid_http(httpSuccess=HTTPCreated, detail="Add user to db successful")


def create_user_resource_permission(permission_name, resource, user_id, db_session):
    check_valid_service_resource_permission(permission_name, resource, db_session)
    resource_id = resource.resource_id
    new_perm = models.UserResourcePermission(resource_id=resource_id, user_id=user_id)
    verify_param(new_perm, notNone=True, httpError=HTTPNotAcceptable,
                 content={u'resource_id': str(resource_id), u'user_id': str(user_id)},
                 msgOnFail="Failed to create permission using specified `resource_id` and `user_id`")
    new_perm.perm_name = permission_name
    evaluate_call(lambda: db_session.add(new_perm), fallback=lambda: db_session.rollback(),
                  httpError=HTTPConflict, msgOnFail="Permission already exist on service for user, cannot add to db",
                  content={u'resource_id': resource_id, u'user_id': user_id, u'permission_name': permission_name})
    return valid_http(httpSuccess=HTTPCreated, detail="Create user resource permission successful",
                      content={u'resource_id': resource_id})


def delete_user_resource_permission(permission_name, resource, user_id, db_session):
    check_valid_service_resource_permission(permission_name, resource, db_session)
    resource_id = resource.resource_id
    del_perm = UserResourcePermissionService.get(user_id, resource_id, permission_name, db_session)
    evaluate_call(lambda: db_session.delete(del_perm), fallback=lambda: db_session.rollback(),
                  httpError=HTTPNotFound, msgOnFail="Could not find user resource permission to delete from db",
                  content={u'resource_id': resource_id, u'user_id': user_id, u'permission_name': permission_name})
    return valid_http(httpSuccess=HTTPOk, detail="Delete user resource permission successful")


def filter_user_permission(resource_permission_tuple_list, user):
    return filter(lambda perm: perm.group is None and perm.type == u'user' and perm.user.user_name == user.user_name,
                  resource_permission_tuple_list)


def get_user_resource_permissions(user, resource, db_session, inherited_permissions=True):
    if resource.owner_user_id == user.id:
        permission_names = models.resource_type_dict[resource.type].permission_names
    else:
        res_perm_tuple_list = resource.perms_for_user(user, db_session=db_session)
        if not inherited_permissions:
            res_perm_tuple_list = filter_user_permission(res_perm_tuple_list, user)
        permission_names = [permission.perm_name for permission in res_perm_tuple_list]
    return list(set(permission_names))  # remove any duplicates that could be incorporated by multiple groups


def get_user_service_permissions(user, service, db_session, inherited_permissions=True):
    if service.owner_user_id == user.id:
        permission_names = service_type_dict[service.type].permission_names
    else:
        svc_perm_tuple_list = service.perms_for_user(user, db_session=db_session)
        if not inherited_permissions:
            svc_perm_tuple_list = filter_user_permission(svc_perm_tuple_list, user)
        permission_names = [permission.perm_name for permission in svc_perm_tuple_list]
    return list(set(permission_names))  # remove any duplicates that could be incorporated by multiple groups


def get_user_resources_permissions_dict(user, db_session, resource_types=None,
                                        resource_ids=None, inherited_permissions=True):
    verify_param(user, notNone=True, httpError=HTTPNotFound,
                 msgOnFail="Invalid user specified to obtain resource permissions")
    res_perm_tuple_list = user.resources_with_possible_perms(resource_ids=resource_ids,
                                                             resource_types=resource_types, db_session=db_session)
    if not inherited_permissions:
        res_perm_tuple_list = filter_user_permission(res_perm_tuple_list, user)
    resources_permissions_dict = {}
    for res_perm in res_perm_tuple_list:
        if res_perm.resource.resource_id not in resources_permissions_dict:
            resources_permissions_dict[res_perm.resource.resource_id] = [res_perm.perm_name]
        else:
            resources_permissions_dict[res_perm.resource.resource_id].append(res_perm.perm_name)

    # remove any duplicates that could be incorporated by multiple groups
    for res_id in resources_permissions_dict:
        resources_permissions_dict[res_id] = list(set(resources_permissions_dict[res_id]))

    return resources_permissions_dict


def get_user_service_resources_permissions_dict(user, service, db_session, inherited_permissions=True):
    resources_under_service = models.resource_tree_service.from_parent_deeper(parent_id=service.resource_id,
                                                                              db_session=db_session)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    return get_user_resources_permissions_dict(user, db_session, resource_types=None, resource_ids=resource_ids,
                                               inherited_permissions=inherited_permissions)


def check_user_info(user_name, email, password, group_name):
    verify_param(user_name, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `user_name` value specified")
    verify_param(len(user_name), isIn=True, httpError=HTTPBadRequest,
                 paramCompare=range(1, 1 + USER_NAME_MAX_LENGTH),
                 msgOnFail="Invalid `user_name` length specified " +
                           "(>{length} characters)".format(length=USER_NAME_MAX_LENGTH))
    verify_param(email, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `email` value specified")
    verify_param(password, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `password` value specified")
    verify_param(group_name, notNone=True, notEmpty=True, httpError=HTTPBadRequest,
                 msgOnFail="Invalid `group_name` value specified")
    verify_param(user_name, paramCompare=[LOGGED_USER], notIn=True, httpError=HTTPConflict,
                 msgOnFail="Invalid `user_name` already logged in")


def get_user_groups_checked(request, user):
    verify_param(user, notNone=True, httpError=HTTPNotFound, msgOnFail="User name not found in db")
    db = request.db
    group_names = evaluate_call(lambda: [group.group_name for group in user.groups], fallback=lambda: db.rollback(),
                                httpError=HTTPInternalServerError, msgOnFail="Failed to obtain groups of user")
    return group_names
