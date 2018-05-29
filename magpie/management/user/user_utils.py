from magpie import *
from api_except import *
from services import service_type_dict
from models import resource_type_dict, resource_tree_service
from management.group.group_utils import check_is_standard_group
from ziggurat_definitions import *


def rollback_delete(db, entry):
    db.rollback()
    entry.delete(db_session=db)


def create_user(user_name, password, email, group_name, db_session):
    """
    When a user is created, he is automatically assigned to a group with the same name.
    He is also added to a default group specified by group_name.
    It is then easier to check permission on resource a user has:
    Check all permission inherited from group: GET /users/user_name/permissions
    Check direct permission of user: GET /groups/user_name/permissions

    :return: `HTTPCreated` if successful
    :raise `HTTPNotAcceptable`:
    :raise `HTTPConflict`:
    :raise `HTTPForbidden`:
    """
    db = db_session
    # Check if group already exist
    group = evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=db),
                          httpError=HTTPForbidden, msgOnFail="Group query was refused by db")
    check_is_standard_group(group, db)
    verify_param(group, notNone=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Group for new user already exists")

    # Create user-group associated to user
    group_check = evaluate_call(lambda: GroupService.by_group_name(group_name=user_name, db_session=db),
                                httpError=HTTPForbidden, msgOnFail="Group check query was refused by db")
    user_check = evaluate_call(lambda: UserService.by_user_name(user_name=user_name, db_session=db),
                               httpError=HTTPForbidden, msgOnFail="User check query was refused by db")
    verify_param(group_check, isNone=True, httpError=HTTPConflict,
                 msgOnFail="User name matches an already existing group name")
    verify_param(user_check, isNone=True, httpError=HTTPConflict,
                 msgOnFail="User name matches an already existing user name")
    group_model = models.Group(group_name=user_name)
    evaluate_call(lambda: db.add(group_model), fallback=lambda: rollback_delete(db, group_model),
                  httpError=HTTPForbidden, msgOnFail="Failed to add group to db")

    # Create user with specified name and newly created group
    user_model = models.User(user_name=user_name, email=email)
    if password:
        user_model.set_password(password)
        user_model.regenerate_security_code()
    evaluate_call(lambda: db.add(user_model), fallback=lambda: rollback_delete(db, group_model),
                  httpError=HTTPForbidden, msgOnFail="Failed to add user to db")

    # Assign user to default group and own group
    new_user = evaluate_call(lambda: UserService.by_user_name(user_name, db_session=db),
                             httpError=HTTPForbidden, msgOnFail="New user query was refused by db")
    group_entry = models.UserGroup(group_id=group.id, user_id=new_user.id)
    evaluate_call(lambda: db.add(group_entry), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Failed to add user-group to db")
    new_group = evaluate_call(lambda: GroupService.by_group_name(user_name, db_session=db),
                              httpError=HTTPForbidden, msgOnFail="New group query was refused by db")
    new_group_entry = models.UserGroup(group_id=new_group.id, user_id=new_user.id)
    evaluate_call(lambda: db.add(new_group_entry), fallback=lambda: db.rollback(),
                  httpError=HTTPForbidden, msgOnFail="Failed to add user-group to db")

    return valid_http(httpSuccess=HTTPCreated, detail="Add user to db successful")


def get_user_resource_permissions(user, resource, db_session, inherited_permissions=True):
    if resource.owner_user_id == user.id:
        permission_names = resource_type_dict[resource.type].permission_names
    else:
        res_perm_tuple_list = resource.perms_for_user(user, db_session=db_session)
        if not inherited_permissions:
            res_perm_tuple_list = filter(lambda perm: perm.group.group_name == user.user_name, res_perm_tuple_list)
        permission_names = [permission.perm_name for permission in res_perm_tuple_list]
    return list(set(permission_names))  # remove any duplicates that could be incorporated by multiple groups


def get_user_service_permissions(user, service, db_session, inherited_permissions=True):
    if service.owner_user_id == user.id:
        permission_names = service_type_dict[service.type].permission_names
    else:
        svc_perm_tuple_list = service.perms_for_user(user, db_session=db_session)
        if not inherited_permissions:
            svc_perm_tuple_list = filter(lambda perm:
                                         perm.group is None and perm.user.user_name == user.user_name, svc_perm_tuple_list)
        permission_names = [permission.perm_name for permission in svc_perm_tuple_list]
    return list(set(permission_names))  # remove any duplicates that could be incorporated by multiple groups


def get_user_resources_permissions_dict(user, db_session, resource_types=None,
                                        resource_ids=None, inherited_permissions=True):
    verify_param(user, notNone=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid user specified to obtain resource permissions")
    res_perm_tuple_list = user.resources_with_possible_perms(resource_ids=resource_ids,
                                                             resource_types=resource_types, db_session=db_session)
    if not inherited_permissions:
        res_perm_tuple_list = filter(lambda perm:
                                     perm.group is None or perm.group.group_name == user.user_name, res_perm_tuple_list)    # TMP replace by type='user'

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
    resources_under_service = resource_tree_service.from_parent_deeper(parent_id=service.resource_id,
                                                                       db_session=db_session)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    return get_user_resources_permissions_dict(user, db_session, resource_types=None, resource_ids=resource_ids,
                                               inherited_permissions=inherited_permissions)


def check_user_info(user_name, email, password, group_name):
    verify_param(user_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `user_name` value specified")
    verify_param(len(user_name), isIn=True, httpError=HTTPNotAcceptable,
                 paramCompare=range(1, 1 + USER_NAME_MAX_LENGTH),
                 msgOnFail="Invalid `user_name` length specified " +
                           "(>{length} characters)".format(length=USER_NAME_MAX_LENGTH))
    verify_param(email, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `email` value specified")
    verify_param(password, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `password` value specified")
    verify_param(group_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `group_name` value specified")
    verify_param(user_name, paramCompare=[LOGGED_USER], notIn=True, httpError=HTTPConflict,
                 msgOnFail="Invalid `user_name` already logged in")
