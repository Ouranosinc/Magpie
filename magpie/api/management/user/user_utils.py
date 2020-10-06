from typing import TYPE_CHECKING

import six
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPOk
)
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource import ResourceService
from ziggurat_foundations.models.services.user import UserService
from ziggurat_foundations.models.services.user_resource_permission import UserResourcePermissionService

from magpie import models
from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.management.resource import resource_utils as ru
from magpie.api.management.service.service_formats import format_service
from magpie.api.management.user import user_formats as uf
from magpie.constants import get_constant
from magpie.permissions import PermissionSet, PermissionType, format_permissions
from magpie.services import service_factory

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Dict, Iterable, List, Optional

    from pyramid.httpexceptions import HTTPException
    from pyramid.request import Request
    from sqlalchemy.orm.session import Session
    from ziggurat_foundations.permissions import PermissionTuple  # noqa

    from magpie.typedefs import ResourcePermissionMap, ServiceOrResourceType, Str, UserServicesType


def create_user(user_name, password, email, group_name, db_session):
    # type: (Str, Optional[Str], Str, Optional[Str], Session) -> HTTPException
    """
    Creates a user if it is permitted and not conflicting. Password must be set to ``None`` if using external identity.

    Created user will immediately assigned membership to the group matching :paramref:`group_name`
    (can be :py:data:`MAGPIE_ANONYMOUS_GROUP` for minimal access). If no group is provided, this anonymous group will
    be applied by default, creating a user effectively without any permissions other than ones set directly for him.

    Furthermore, the user will also *always* be associated with :py:data:`MAGPIE_ANONYMOUS_GROUP` (if not already
    explicitly or implicitly requested with :paramref:`group_name`) to allow access to resources with public permission.
    Argument :paramref:`group_name` **MUST** be an existing group if provided.

    :returns: valid HTTP response on successful operation.
    """

    def _get_group(grp_name):
        # type: (Str) -> models.Group
        ax.verify_param(grp_name, not_none=True, not_empty=True, matches=True,
                        param_compare=ax.PARAM_REGEX, param_name="group_name",
                        http_error=HTTPBadRequest, msg_on_fail=s.UserGroup_Check_BadRequestResponseSchema.description)
        grp = ax.evaluate_call(lambda: GroupService.by_group_name(grp_name, db_session=db_session),
                               http_error=HTTPForbidden,
                               msg_on_fail=s.UserGroup_GET_ForbiddenResponseSchema.description)
        ax.verify_param(grp, not_none=True, http_error=HTTPNotFound, with_param=False,
                        msg_on_fail=s.UserGroup_Check_NotFoundResponseSchema.description)
        return grp

    # Check that group already exists
    if group_name is None:
        group_name = get_constant("MAGPIE_ANONYMOUS_GROUP")
    is_internal = password is not None
    check_user_info(user_name, email, password, group_name, check_password=is_internal)
    group_checked = _get_group(group_name)

    # Check if user already exists
    user_checked = ax.evaluate_call(lambda: UserService.by_user_name(user_name=user_name, db_session=db_session),
                                    http_error=HTTPForbidden,
                                    msg_on_fail=s.User_Check_ForbiddenResponseSchema.description)
    ax.verify_param(user_checked, is_none=True, with_param=False, http_error=HTTPConflict,
                    msg_on_fail=s.User_Check_ConflictResponseSchema.description)

    # Create user with specified name and group to assign
    new_user = models.User(user_name=user_name, email=email)  # noqa
    if is_internal:
        UserService.set_password(new_user, password)
        UserService.regenerate_security_code(new_user)
    ax.evaluate_call(lambda: db_session.add(new_user), fallback=lambda: db_session.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.Users_POST_ForbiddenResponseSchema.description)
    # Fetch user to update fields
    new_user = ax.evaluate_call(lambda: UserService.by_user_name(user_name, db_session=db_session),
                                http_error=HTTPForbidden,
                                msg_on_fail=s.UserNew_POST_ForbiddenResponseSchema.description)

    def _add_to_group(usr, grp):
        # type: (models.User, models.Group) -> None
        group_entry = models.UserGroup(group_id=grp.id, user_id=usr.id)  # noqa
        ax.evaluate_call(lambda: db_session.add(group_entry), fallback=lambda: db_session.rollback(),
                         http_error=HTTPForbidden, msg_on_fail=s.UserGroup_GET_ForbiddenResponseSchema.description)

    # Assign user to group
    new_user_groups = [group_name]
    _add_to_group(new_user, group_checked)
    # Also add user to anonymous group if not already done
    anonym_grp_name = get_constant("MAGPIE_ANONYMOUS_GROUP")
    if group_checked.group_name != anonym_grp_name:
        _add_to_group(new_user, _get_group(anonym_grp_name))
        new_user_groups.append(anonym_grp_name)

    return ax.valid_http(http_success=HTTPCreated, detail=s.Users_POST_CreatedResponseSchema.description,
                         content={"user": uf.format_user(new_user, new_user_groups)})


def create_user_resource_permission_response(user, resource, permission, db_session, overwrite=False):
    # type: (models.User, ServiceOrResourceType, PermissionSet, Session, bool) -> HTTPException
    """
    Creates a permission on a user/resource combination if it is permitted, and optionally not conflicting.

    :param user: user for which to create/update the permission.
    :param resource: service or resource for which to create the permission.
    :param permission: permission with modifiers to be applied.
    :param db_session: database connection.
    :param overwrite:
        If the corresponding `(user, resource, permission[name])` exists, there is a conflict.
        Conflict is considered only by permission-name regardless of other modifiers.
        If overwrite is ``False``, the conflict will be raised and not be applied.
        If overwrite is ``True``, the permission modifiers will be replaced by the new ones, or created if missing.
    :returns: valid HTTP response on successful operation.
    """
    ru.check_valid_service_or_resource_permission(permission.name, resource, db_session)
    res_id = resource.resource_id
    exist_perm = get_similar_user_resource_permission(user, resource, permission, db_session=db_session)

    permission.type = PermissionType.APPLIED
    err_content = {"resource_id": res_id, "user_id": user.id,
                   "permission_name": str(permission), "permission": permission.json()}
    http_success = HTTPCreated
    http_detail = s.UserResourcePermissions_POST_CreatedResponseSchema.description
    if overwrite and exist_perm:
        # skip similar permission lookup since we already did it
        http_success = HTTPOk
        http_detail = s.UserResourcePermissions_PUT_OkResponseSchema.description
        delete_user_resource_permission_response(user, resource, exist_perm, db_session=db_session, similar=False)
    else:
        ax.verify_param(exist_perm, is_none=True, with_param=False, http_error=HTTPConflict, content=err_content,
                        msg_on_fail=s.UserResourcePermissions_POST_ConflictResponseSchema.description)

    new_perm = models.UserResourcePermission(resource_id=res_id, user_id=user.id, perm_name=str(permission))
    ax.verify_param(new_perm, not_none=True, http_error=HTTPForbidden,
                    content={"resource_id": res_id, "user_id": user.id},
                    msg_on_fail=s.UserResourcePermissions_POST_ForbiddenResponseSchema.description)
    ax.evaluate_call(lambda: db_session.add(new_perm), fallback=lambda: db_session.rollback(),
                     http_error=HTTPForbidden, content=err_content,
                     msg_on_fail=s.UserResourcePermissions_POST_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=http_success, content=err_content, detail=http_detail)


def delete_user_group(user, group, db_session):
    # type: (models.User, models.Group, Session) -> None
    """
    Deletes a user-group relationship (user membership to a group).

    :returns: nothing - user-group is deleted.
    :raises HTTPNotFound: if the combination cannot be found.
    """
    def del_usr_grp(usr, grp):
        db_session.query(models.UserGroup) \
            .filter(models.UserGroup.user_id == usr.id) \
            .filter(models.UserGroup.group_id == grp.id) \
            .delete()

    ax.verify_param(group.group_name, not_equal=True, param_compare=get_constant("MAGPIE_ANONYMOUS_GROUP"),
                    param_name="group_name", http_error=HTTPForbidden,
                    msg_on_fail=s.UserGroup_DELETE_ForbiddenResponseSchema.description)
    ax.evaluate_call(lambda: del_usr_grp(user, group), fallback=lambda: db_session.rollback(),
                     http_error=HTTPNotFound, msg_on_fail=s.UserGroup_DELETE_NotFoundResponseSchema.description,
                     content={"user_name": user.user_name, "group_name": group.group_name})


def delete_user_resource_permission_response(user, resource, permission, db_session, similar=True):
    # type: (models.User, ServiceOrResourceType, PermissionSet, Session, bool) -> HTTPException
    """
    Get validated response on deleted user resource permission.

    :param user: user for which to delete the permission.
    :param resource: service or resource for which to delete the permission.
    :param permission: permission with modifiers to be deleted.
    :param db_session: database connection.
    :param similar:
        Allow matching provided permission against any similar database permission. Otherwise, must match exactly.
    :returns: valid HTTP response on successful operations.
    :raises HTTPException: error HTTP response of corresponding situation.
    """
    ru.check_valid_service_or_resource_permission(permission.name, resource, db_session)
    res_id = resource.resource_id
    if similar:
        found_perm = get_similar_user_resource_permission(user, resource, permission, db_session)
    else:
        found_perm = permission
    del_perm = UserResourcePermissionService.get(user.id, res_id, str(found_perm), db_session)
    permission.type = PermissionType.APPLIED
    err_content = {"resource_id": res_id, "user_id": user.id,
                   "permission_name": str(permission), "permission": permission.json()}
    ax.verify_param(del_perm, not_none=True, http_error=HTTPNotFound, content=err_content,
                    msg_on_fail=s.UserResourcePermissionName_DELETE_NotFoundResponseSchema.description)
    ax.evaluate_call(lambda: db_session.delete(del_perm), fallback=lambda: db_session.rollback(),
                     http_error=HTTPNotFound, content=err_content,
                     msg_on_fail=s.UserResourcePermissionName_DELETE_NotFoundResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.UserResourcePermissionName_DELETE_OkResponseSchema.description)


def filter_user_permission(resource_permission_list, user):
    # type: (List[PermissionTuple], models.User) -> Iterable[PermissionTuple]
    """
    Retrieves only direct user permissions on resources amongst a list of user/group resource/service permissions.
    """
    def is_user_perm(perm):
        return perm.group is None and perm.type == "user" and perm.user.user_name == user.user_name
    return filter(is_user_perm, resource_permission_list)


def get_similar_user_resource_permission(user, resource, permission, db_session):
    # type: (models.User, ServiceOrResourceType, PermissionSet, Session) -> Optional[PermissionSet]
    """
    Obtains the user service/resource permission that corresponds to the provided one.

    Lookup considers only *similar* applied permission such that other permission modifiers don't affect comparison.
    """
    permission.type = PermissionType.APPLIED
    err_content = {"resource_id": resource.resource_id, "user_id": user.id,
                   "permission_name": str(permission), "permission": permission.json()}

    def is_similar_permission():
        perms_list = ResourceService.direct_perms_for_user(resource, user, db_session=db_session)
        perms_list = [PermissionSet(perm) for perm in perms_list]
        return [perm for perm in perms_list if perm.like(permission)]

    similar_perms = ax.evaluate_call(lambda: is_similar_permission(),
                                     http_error=HTTPForbidden, content=err_content,
                                     msg_on_fail=s.UserResourcePermissions_Check_ErrorResponseSchema.description)
    if not similar_perms:
        return None
    found_perm = similar_perms[0]
    found_perm.type = PermissionType.DIRECT
    return found_perm


def get_user_resource_permissions_response(user, resource, request,
                                           inherit_groups_permissions=True, effective_permissions=False):
    # type: (models.User, ServiceOrResourceType, Request, bool, bool) -> HTTPException
    """
    Retrieves user resource permissions with or without inherited group permissions. Alternatively retrieves the
    effective user resource permissions, where group permissions are implied as `True`.

    :returns: valid HTTP response on successful operations.
    :raises HTTPException: error HTTP response of corresponding situation.
    """
    db_session = request.db

    def get_usr_res_perms():
        perm_type = None
        if resource.owner_user_id == user.id:
            # FIXME: no 'magpie.models.Resource.permissions' - ok for now because no owner handling...
            perm_type = PermissionType.OWNED
            res_perm_list = models.RESOURCE_TYPE_DICT[resource.type].permissions
        else:
            if effective_permissions:
                svc = ru.get_resource_root_service_impl(resource, request)
                res_perm_list = svc.effective_permissions(resource, user)
                perm_type = PermissionType.EFFECTIVE
            else:
                if inherit_groups_permissions:
                    res_perm_list = ResourceService.perms_for_user(resource, user, db_session=db_session)
                    perm_type = PermissionType.INHERITED
                else:
                    res_perm_list = ResourceService.direct_perms_for_user(resource, user, db_session=db_session)
                    perm_type = PermissionType.DIRECT
        return format_permissions(res_perm_list, perm_type)

    permissions = ax.evaluate_call(
        lambda: get_usr_res_perms(),
        fallback=lambda: db_session.rollback(), http_error=HTTPInternalServerError,
        msg_on_fail=s.UserServicePermissions_GET_NotFoundResponseSchema.description,
        content={"resource_name": str(resource.resource_name), "user_name": str(user.user_name)})
    return ax.valid_http(http_success=HTTPOk, content=permissions,
                         detail=s.UserResourcePermissions_GET_OkResponseSchema.description)


def get_user_services(user, request, cascade_resources=False,
                      inherit_groups_permissions=False, format_as_list=False):
    # type: (models.User, Request, bool, bool, bool) -> UserServicesType
    """
    Returns services by type with corresponding services by name containing sub-dict information.

    :param user: user for which to find services
    :param request: request with database session connection
    :param cascade_resources:
        If ``False``, return only services which the :term:`User` has :term:`Immediate Permissions` on specialized
        top-level resources corresponding to services.
        Otherwise, return every service that has at least one sub-resource with permissions (children at any-level).
        In both cases, the *permissions* looked for consider either only :term:`Direct Permissions` or any
        :term:`Inherited Permissions` according to the value of :paramref:`inherit_groups_permissions`.
    :param inherit_groups_permissions:
        If ``False``, return only user-specific service/sub-resources :term:`Direct Permissions`.
        Otherwise, resolve :term:`Inherited Permissions` using all groups the user is member of.
    :param format_as_list:
        returns as list of service dict information (not grouped by type and by name)
    :return:
        Only services which the user as :term:`Direct Permissions` or considering all tree hierarchy,
        and for each case, either considering only user permissions or every :term:`Inherited Permissions`,
        according to provided options.
    :rtype:
        Mapping of services by type to corresponding services by name containing each sub-mapping of their information,
        unless :paramref:`format_as_list` is ``True``, in which case a flat list of service information is returned.
    """
    db_session = request.db
    resource_type = None if cascade_resources else [models.Service.resource_type]
    res_perm_dict = get_user_resources_permissions_dict(user, resource_types=resource_type, request=request,
                                                        inherit_groups_permissions=inherit_groups_permissions)
    perm_type = PermissionType.INHERITED if inherit_groups_permissions else PermissionType.DIRECT
    services = {}
    for resource_id, perms in res_perm_dict.items():
        resource = ResourceService.by_resource_id(resource_id=resource_id, db_session=db_session)
        is_service = resource.resource_type == models.Service.resource_type_name

        if not is_service:
            # if any children resource had user/group permissions, minimally return its root service without
            # any immediate permission, otherwise (cascade off) it is skipped and not returned at all in response
            if not cascade_resources:
                continue
            perms = []

        svc = ru.get_resource_root_service_impl(resource, request)
        if svc.service_type not in services:
            services[svc.service_type] = {}
        svc_name = svc.service.resource_name
        svc_type = svc.service_type

        # if service was not already added, add it (could be directly its permissions, or empty via children resource)
        # otherwise, set explicit immediate permissions on service instead of empty children resource permissions
        if svc_name not in services[svc_type] or is_service:
            svc_json = format_service(svc.service, perms, perm_type, show_private_url=False)
            services[svc_type][svc_name] = svc_json

    if not format_as_list:
        return services

    services_list = list()
    for svc_type in services:
        for svc_name in services[svc_type]:
            services_list.append(services[svc_type][svc_name])
    return services_list


def get_user_service_permissions(user, service, request, inherit_groups_permissions=True):
    # type: (models.User, models.Service, Request, bool) -> List[PermissionSet]
    if service.owner_user_id == user.id:
        perm_type = PermissionType.OWNED
        usr_svc_perms = service_factory(service, request).permissions
    else:
        if inherit_groups_permissions:
            perm_type = PermissionType.INHERITED
            usr_svc_perms = ResourceService.perms_for_user(service, user, db_session=request.db)
        else:
            perm_type = PermissionType.DIRECT
            usr_svc_perms = ResourceService.direct_perms_for_user(service, user, db_session=request.db)
    return [PermissionSet(p, typ=perm_type) for p in usr_svc_perms]


def get_user_resources_permissions_dict(user, request, resource_types=None,
                                        resource_ids=None, inherit_groups_permissions=True):
    # type: (models.User, Request, Optional[List[Str]], Optional[List[int]], bool) -> Dict[Str, PermissionSet]
    """
    Creates a dictionary of resources by id with corresponding permissions of the user.

    :param user: user for which to find services
    :param request: request with database session connection
    :param resource_types: filter the search query with specified resource types
    :param resource_ids: filter the search query with specified resource ids
    :param inherit_groups_permissions:
        If ``False``, return only user-specific resource permissions.
        Otherwise, resolve inherited permissions using all groups the user is member of.
    :return:
        Only services which the user as permissions on, or including all :term:`Inherited Permissions`, according to
        :paramref:`inherit_groups_permissions` argument.
    """
    ax.verify_param(user, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.UserResourcePermissions_GET_NotFoundResponseSchema.description)
    res_perm_tuple_list = UserService.resources_with_possible_perms(
        user, resource_ids=resource_ids, resource_types=resource_types, db_session=request.db)
    if not inherit_groups_permissions:
        res_perm_tuple_list = filter_user_permission(res_perm_tuple_list, user)
    resources_permissions_dict = {}
    for res_perm in res_perm_tuple_list:
        if res_perm.resource.resource_id not in resources_permissions_dict:
            resources_permissions_dict[res_perm.resource.resource_id] = [PermissionSet(res_perm)]
        else:
            resources_permissions_dict[res_perm.resource.resource_id].append(PermissionSet(res_perm))

    # remove any duplicates that could be incorporated by multiple groups
    for res_id in resources_permissions_dict:
        resources_permissions_dict[res_id] = sorted(set(resources_permissions_dict[res_id]))

    return resources_permissions_dict


def get_user_service_resources_permissions_dict(user, service, request, inherit_groups_permissions=True):
    # type: (models.User, models.Service, Request, bool) -> ResourcePermissionMap
    """
    Retrieves all permissions the user has for all resources nested under the service.

    The retrieved permissions can either include only direct permissions or also include inherited group permissions.

    :returns: dictionary of resource IDs with corresponding permissions.
    """
    resources_under_service = models.RESOURCE_TREE_SERVICE.from_parent_deeper(parent_id=service.resource_id,
                                                                              db_session=request.db)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    if not resource_ids:
        return {}  # return immediately, otherwise empty list generates dict of all existing resources (i.e. no-filter)
    return get_user_resources_permissions_dict(user, request, resource_types=None, resource_ids=resource_ids,
                                               inherit_groups_permissions=inherit_groups_permissions)


def check_user_info(user_name=None, email=None, password=None, group_name=None,  # required unless disabled explicitly
                    check_name=True, check_email=True, check_password=True, check_group=True):
    # type: (Str, Str, Str, Str, bool, bool, bool, bool) -> None
    """
    Validates provided user information to ensure they are adequate for user creation.

    Using ``check_`` prefixed arguments, individual field checks can be disabled (check all by default).

    :raises HTTPException: appropriate error for the invalid field value or format that was checked as applicable.
    :returns: nothing if all enabled checks are successful.
    """
    if check_name:
        ax.verify_param(user_name, not_none=True, not_empty=True, param_name="user_name",
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_UserNameValue_BadRequestResponseSchema.description)
        ax.verify_param(user_name, matches=True, param_name="user_name", param_compare=ax.PARAM_REGEX,
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_UserNameValue_BadRequestResponseSchema.description)
        name_range = range(1, 1 + get_constant("MAGPIE_USER_NAME_MAX_LENGTH"))
        ax.verify_param(len(user_name), is_in=True, param_name="user_name", param_compare=name_range,
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_UserNameSize_BadRequestResponseSchema.description)
        name_logged = get_constant("MAGPIE_LOGGED_USER")
        ax.verify_param(user_name, param_compare=name_logged, not_equal=True, param_name="user_name",
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_ReservedKeyword_BadRequestResponseSchema.description)
    if check_email:
        ax.verify_param(email, not_none=True, not_empty=True, param_name="email",
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_Email_BadRequestResponseSchema.description)
        ax.verify_param(email, matches=True, param_compare=ax.EMAIL_REGEX, param_name="email",
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_Email_BadRequestResponseSchema.description)
    if check_password:
        ax.verify_param(password, not_none=True, not_empty=True, param_name="password",
                        is_type=True, param_compare=six.string_types,  # no match since it can be any character
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_PasswordValue_BadRequestResponseSchema.description)
        ax.verify_param(len(password), not_in=True, param_name="password",
                        param_compare=range(get_constant("MAGPIE_PASSWORD_MIN_LENGTH")),
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_PasswordSize_BadRequestResponseSchema.description)
    if check_group:
        ax.verify_param(group_name, not_none=True, not_empty=True, param_name="group_name",
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_GroupName_BadRequestResponseSchema.description)
        ax.verify_param(group_name, matches=True, param_name="group_name", param_compare=ax.PARAM_REGEX,
                        http_error=HTTPBadRequest,
                        msg_on_fail=s.Users_CheckInfo_GroupName_BadRequestResponseSchema.description)


def get_user_groups_checked(user, db_session):
    # type: (models.User, Session) -> List[Str]
    """
    Obtains the validated list of group names from a pre-validated user.
    """
    ax.verify_param(user, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.Groups_CheckInfo_NotFoundResponseSchema.description)
    group_names = ax.evaluate_call(lambda: [group.group_name for group in user.groups],  # noqa
                                   fallback=lambda: db_session.rollback(), http_error=HTTPForbidden,
                                   msg_on_fail=s.Groups_CheckInfo_ForbiddenResponseSchema.description)
    return sorted(group_names)
