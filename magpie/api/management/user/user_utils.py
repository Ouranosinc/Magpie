from typing import TYPE_CHECKING

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
from magpie.api.management.resource.resource_utils import check_valid_service_or_resource_permission
from magpie.api.management.service.service_formats import format_service
from magpie.api.management.user import user_formats as uf
from magpie.constants import get_constant
from magpie.permissions import convert_permission, format_permissions
from magpie.services import service_factory

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.services import ServiceInterface  # noqa: F401
    from pyramid.httpexceptions import HTTPException
    from pyramid.request import Request
    from sqlalchemy.orm.session import Session
    from magpie.typedefs import (  # noqa: F401
        Any, Str, Dict, Iterable, List, Optional, ResourcePermissionType, UserServicesType, ServiceOrResourceType
    )
    from magpie.permissions import Permission  # noqa: F401


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
        ax.verify_param(grp, not_none=True, http_error=HTTPNotFound, param_name="group_name",
                        msg_on_fail=s.UserGroup_Check_NotFoundResponseSchema.description)
        return grp

    # Check that group already exists
    if group_name is None:
        group_name = get_constant("MAGPIE_ANONYMOUS_GROUP")
    check_user_info(user_name, email, password, group_name)
    group_checked = _get_group(group_name)

    # Check if user already exists
    user_checked = ax.evaluate_call(lambda: UserService.by_user_name(user_name=user_name, db_session=db_session),
                                    http_error=HTTPForbidden,
                                    msg_on_fail=s.User_Check_ForbiddenResponseSchema.description)
    ax.verify_param(user_checked, is_none=True, with_param=False, http_error=HTTPConflict,
                    msg_on_fail=s.User_Check_ConflictResponseSchema.description)

    # Create user with specified name and group to assign
    new_user = models.User(user_name=user_name, email=email)  # noqa
    if password:
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


def create_user_resource_permission_response(user, resource, permission, db_session):
    # type: (models.User, ServiceOrResourceType, Permission, Session) -> HTTPException
    """
    Creates a permission on a user/resource combination if it is permitted and not conflicting.

    :returns: valid HTTP response on successful operation.
    """
    check_valid_service_or_resource_permission(permission.value, resource, db_session)
    res_id = resource.resource_id
    existing_perm = UserResourcePermissionService.by_resource_user_and_perm(
        user_id=user.id, resource_id=res_id, perm_name=permission.value, db_session=db_session)
    ax.verify_param(existing_perm, is_none=True, with_param=False, http_error=HTTPConflict,
                    content={"resource_id": res_id, "user_id": user.id, "permission_name": permission.value},
                    msg_on_fail=s.UserResourcePermissions_POST_ConflictResponseSchema.description)

    new_perm = models.UserResourcePermission(resource_id=res_id, user_id=user.id, perm_name=permission.value)  # noqa
    usr_res_data = {"resource_id": res_id, "user_id": user.id, "permission_name": permission.value}
    ax.verify_param(new_perm, not_none=True, http_error=HTTPForbidden,
                    content={"resource_id": res_id, "user_id": user.id},
                    msg_on_fail=s.UserResourcePermissions_POST_ForbiddenResponseSchema.description)
    ax.evaluate_call(lambda: db_session.add(new_perm), fallback=lambda: db_session.rollback(),
                     http_error=HTTPForbidden, content=usr_res_data,
                     msg_on_fail=s.UserResourcePermissions_POST_ForbiddenResponseSchema.description)
    return ax.valid_http(http_success=HTTPCreated, content=usr_res_data,
                         detail=s.UserResourcePermissions_POST_CreatedResponseSchema.description)


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

    ax.evaluate_call(lambda: del_usr_grp(user, group), fallback=lambda: db_session.rollback(),
                     http_error=HTTPNotFound, msg_on_fail=s.UserGroup_DELETE_NotFoundResponseSchema.description,
                     content={"user_name": user.user_name, "group_name": group.group_name})


def delete_user_resource_permission_response(user, resource, permission, db_session):
    # type: (models.User, ServiceOrResourceType, Permission, Session) -> HTTPException
    """
    Get validated response on deleted user resource permission.

    :returns: valid HTTP response on successful operations.
    :raises HTTPException: error HTTP response of corresponding situation.
    """
    check_valid_service_or_resource_permission(permission.value, resource, db_session)
    res_id = resource.resource_id
    del_perm = UserResourcePermissionService.get(user.id, res_id, permission.value, db_session)
    ax.evaluate_call(lambda: db_session.delete(del_perm), fallback=lambda: db_session.rollback(),
                     http_error=HTTPNotFound,
                     msg_on_fail=s.UserResourcePermissions_DELETE_NotFoundResponseSchema.description,
                     content={"resource_id": res_id, "user_id": user.id, "permission_name": permission.value})
    return ax.valid_http(http_success=HTTPOk, detail=s.UserResourcePermissions_DELETE_OkResponseSchema.description)


def get_resource_root_service(resource, request):
    # type: (models.Resource, Request) -> ServiceInterface
    """
    Retrieves the service class corresponding to the specified resource's root service-resource.
    """
    if resource.resource_type == models.Service.resource_type_name:
        res_root_svc = resource
    else:
        res_root_svc = ResourceService.by_resource_id(resource.root_service_id, db_session=request.db)
    return service_factory(res_root_svc, request)


def filter_user_permission(resource_permission_list, user):
    # type: (List[ResourcePermissionType], models.User) -> Iterable[ResourcePermissionType]
    """
    Retrieves only direct user permissions on resources amongst a list of user/group resource/service permissions.
    """
    def is_user_perm(perm):
        return perm.group is None and perm.type == "user" and perm.user.user_name == user.user_name
    return filter(is_user_perm, resource_permission_list)


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
        if resource.owner_user_id == user.id:
            res_perm_list = models.RESOURCE_TYPE_DICT[resource.type].permissions
        else:
            if effective_permissions:
                svc = get_resource_root_service(resource, request)
                res_perm_list = svc.effective_permissions(resource, user)
            else:
                res_perm_list = ResourceService.perms_for_user(resource, user, db_session=db_session)
                if not inherit_groups_permissions:
                    res_perm_list = filter_user_permission(res_perm_list, user)
        return format_permissions(res_perm_list)

    perm_names = ax.evaluate_call(
        lambda: get_usr_res_perms(),
        fallback=lambda: db_session.rollback(), http_error=HTTPInternalServerError,
        msg_on_fail=s.UserServicePermissions_GET_NotFoundResponseSchema.description,
        content={"resource_name": str(resource.resource_name), "user_name": str(user.user_name)})
    return ax.valid_http(http_success=HTTPOk, content={"permission_names": perm_names},
                         detail=s.UserResourcePermissions_GET_OkResponseSchema.description)


def get_user_services(user, request, cascade_resources=False,
                      inherit_groups_permissions=False, format_as_list=False):
    # type: (models.User, Request, bool, bool, bool) -> UserServicesType
    """
    Returns services by type with corresponding services by name containing sub-dict information.

    :param user: user for which to find services
    :param request: request with database session connection
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
        unless `format_as_list` is `True`
    """
    db_session = request.db
    resource_type = None if cascade_resources else [models.Service.resource_type]
    res_perm_dict = get_user_resources_permissions_dict(user, resource_types=resource_type, request=request,
                                                        inherit_groups_permissions=inherit_groups_permissions)

    services = {}
    for resource_id, perms in res_perm_dict.items():
        resource = ResourceService.by_resource_id(resource_id=resource_id, db_session=db_session)
        service_id = resource.root_service_id or resource.resource_id

        is_service = resource.resource_type == models.Service.resource_type_name

        if not is_service:
            if not cascade_resources:
                continue
            perms = get_resource_root_service(resource, request).permissions

        svc = db_session.query(models.Service).filter_by(resource_id=service_id).first()

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


def get_user_service_permissions(user, service, request, inherit_groups_permissions=True):
    # type: (models.User, models.Service, Request, bool) -> List[Permission]
    if service.owner_user_id == user.id:
        usr_svc_perms = service_factory(service, request).permissions
    else:
        usr_svc_perms = ResourceService.perms_for_user(service, user, db_session=request.db)
        if not inherit_groups_permissions:
            usr_svc_perms = filter_user_permission(usr_svc_perms, user)
    return [convert_permission(p) for p in usr_svc_perms]


def get_user_resources_permissions_dict(user, request, resource_types=None,
                                        resource_ids=None, inherit_groups_permissions=True):
    # type: (models.User, Request, Optional[List[Str]], Optional[List[int]], bool) -> Dict[Str, Any]
    """
    Creates a dictionary of resources by id with corresponding permissions of the user.

    :param user: user for which to find services
    :param request: request with database session connection
    :param resource_types: filter the search query with specified resource types
    :param resource_ids: filter the search query with specified resource ids
    :param inherit_groups_permissions:
        If `False`, return only user-specific resource permissions.
        Otherwise, resolve inherited permissions using all groups the user is member of.
    :return: only services which the user as *Direct* or *Inherited* permissions, according to `inherit_from_resources`
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
            resources_permissions_dict[res_perm.resource.resource_id] = [res_perm.perm_name]
        else:
            resources_permissions_dict[res_perm.resource.resource_id].append(res_perm.perm_name)

    # remove any duplicates that could be incorporated by multiple groups
    for res_id in resources_permissions_dict:
        resources_permissions_dict[res_id] = sorted(set(resources_permissions_dict[res_id]))

    return resources_permissions_dict


def get_user_service_resources_permissions_dict(user, service, request, inherit_groups_permissions=True):
    # type: (models.User, models.Service, Request, bool) -> Dict[Str, Any]
    resources_under_service = models.RESOURCE_TREE_SERVICE.from_parent_deeper(parent_id=service.resource_id,
                                                                              db_session=request.db)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    return get_user_resources_permissions_dict(user, request, resource_types=None, resource_ids=resource_ids,
                                               inherit_groups_permissions=inherit_groups_permissions)


def check_user_info(user_name, email, password, group_name):
    # type: (Str, Str, Str, Str) -> None
    """Validates provided user information to ensure they are adequate for user creation."""
    ax.verify_param(user_name, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                    param_name="user_name",
                    msg_on_fail=s.Users_CheckInfo_Name_BadRequestResponseSchema.description)
    ax.verify_param(user_name, matches=True, http_error=HTTPBadRequest,
                    param_name="user_name", param_compare=ax.PARAM_REGEX,
                    msg_on_fail=s.Users_CheckInfo_Name_BadRequestResponseSchema.description)
    ax.verify_param(len(user_name), is_in=True, http_error=HTTPBadRequest,
                    param_name="user_name", param_compare=range(1, 1 + get_constant("MAGPIE_USER_NAME_MAX_LENGTH")),
                    msg_on_fail=s.Users_CheckInfo_Size_BadRequestResponseSchema.description)
    ax.verify_param(user_name, param_compare=get_constant("MAGPIE_LOGGED_USER"), not_equal=True,
                    param_name="user_name", http_error=HTTPBadRequest,
                    msg_on_fail=s.Users_CheckInfo_ReservedKeyword_BadRequestResponseSchema.description)
    ax.verify_param(email, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                    param_name="email", msg_on_fail=s.Users_CheckInfo_Email_BadRequestResponseSchema.description)
    ax.verify_param(email, matches=True, param_compare=ax.EMAIL_REGEX, http_error=HTTPBadRequest,
                    param_name="email", msg_on_fail=s.Users_CheckInfo_Email_BadRequestResponseSchema.description)
    ax.verify_param(password, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                    param_name="password",
                    msg_on_fail=s.Users_CheckInfo_Password_BadRequestResponseSchema.description)
    ax.verify_param(group_name, not_none=True, not_empty=True, http_error=HTTPBadRequest,
                    param_name="group_name",
                    msg_on_fail=s.Users_CheckInfo_GroupName_BadRequestResponseSchema.description)
    ax.verify_param(group_name, matches=True, http_error=HTTPBadRequest,
                    param_name="group_name", param_compare=ax.PARAM_REGEX,
                    msg_on_fail=s.Users_CheckInfo_GroupName_BadRequestResponseSchema.description)


def get_user_groups_checked(request, user):
    # type: (Request, models.User) -> List[Str]
    """Obtains the validated list of group names from a pre-validated user."""
    ax.verify_param(user, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.Groups_CheckInfo_NotFoundResponseSchema.description)
    group_names = ax.evaluate_call(lambda: [group.group_name for group in user.groups],  # noqa
                                   fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                   msg_on_fail=s.Groups_CheckInfo_ForbiddenResponseSchema.description)
    return sorted(group_names)
