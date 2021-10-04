from secrets import compare_digest
from typing import TYPE_CHECKING

import six
import transaction
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPOk
)
from pyramid.settings import asbool
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
from magpie.api.webhooks import (
    WebhookAction,
    generate_callback_url,
    get_permission_update_params,
    process_webhook_requests
)
from magpie.constants import get_constant
from magpie.permissions import PermissionSet, PermissionType, format_permissions
from magpie.services import SERVICE_TYPE_DICT, service_factory
from magpie.utils import get_logger

LOGGER = get_logger(__name__)

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Iterable, List, Optional, Tuple

    from pyramid.httpexceptions import HTTPException
    from pyramid.request import Request
    from sqlalchemy.orm.session import Session
    from ziggurat_foundations.permissions import PermissionTuple  # noqa

    from magpie.typedefs import (
        ResolvablePermissionType,
        ResourcePermissionMap,
        ServiceOrResourceType,
        Str,
        UserServicesType
    )


def create_user(user_name,              # type: Str
                password,               # type: Optional[Str]
                email,                  # type: Str
                group_name,             # type: Optional[Str]
                db_session,             # type: Session
                **extra_fields          # type: Any
                ):                      # type: (...) -> HTTPException
    """
    Creates a :term:`User` if it is permitted and not conflicting with existing ones.

    Password must be set to ``None`` if using an external identity or skip its encrypted value generation.

    Created :term:`User` will immediately be assigned membership to the group matching :paramref:`group_name`
    (can be :py:data:`MAGPIE_ANONYMOUS_GROUP` for minimal access). If no group is provided, this anonymous group will
    be applied by default, creating a user effectively without any permissions other than ones set directly for him and
    inherited from :ref:`perm_public_access`.

    Furthermore, the :term:`User` *always* gets associated with :py:data:`MAGPIE_ANONYMOUS_GROUP` (if not already
    explicitly or implicitly requested with :paramref:`group_name`) to allow access to resources with public permission.
    This means that when :paramref:`group_name` is provided with another name than :py:data:`MAGPIE_ANONYMOUS_GROUP`,
    the :term:`User` will have two memberships initially.

    Argument :paramref:`group_name` **MUST** be an existing group if provided.

    .. note::
        In order to properly handle subscribed :term:`Webhook` that could request to change the user status to an
        error following a failing external operation, the created user is immediately committed. This way, following
        requests will have access to the instance from the database. Because of this requirement, any operation that
        desire an handle to the created :class:`User` instance should retrieve it again from the database session.

    :param user_name: Unique name of the user to validate and employ for creation.
    :param password:
        Raw password of the user to validate and employ for creation.
        If Skipped if ``None``. Otherwise, apply hash encryption on the value.
    :param email: User email to be validated and employed for creation.
    :param group_name: Group name to associate the user with at creation time.
    :param db_session: database connection.
    :param extra_fields:
        Additional fields that should be set for the user. Must be known properties of the instance.
    :returns: valid HTTP response on successful operation, or the :class:`User` when requested.
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

    # check if user already exists
    user_checked = ax.evaluate_call(
        lambda: models.UserSearchService.by_name_or_email(user_name=user_name, email=email, db_session=db_session),
        http_error=HTTPForbidden, msg_on_fail=s.User_Check_ForbiddenResponseSchema.description)
    ax.verify_param(user_checked, is_none=True, with_param=False, http_error=HTTPConflict,
                    msg_on_fail=s.User_Check_ConflictResponseSchema.description)

    # Create user with specified name and group to assign
    new_user = models.User(user_name=user_name, email=email)  # noqa
    if is_internal:
        UserService.set_password(new_user, password)  # already regenerates security code
    for field, value in extra_fields.items():
        if hasattr(new_user, field):
            setattr(new_user, field, value)
    if "user_password" in extra_fields:
        UserService.regenerate_security_code(new_user)  # force if reset with explicit hash
    ax.evaluate_call(lambda: db_session.add(new_user), fallback=lambda: db_session.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.Users_POST_ForbiddenResponseSchema.description)
    # Fetch user to update auto-generated fields (i.e.: id)
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

    user_content = uf.format_user(new_user, new_user_groups)

    callback_url = generate_callback_url(models.TokenOperation.WEBHOOK_USER_STATUS_ERROR, db_session, user=new_user)
    # Force commit before sending the webhook requests, so that the user's status is editable if a webhook error occurs
    transaction.commit()

    # note: after committed transaction, 'new_user' object becomes detached and cannot be used directly
    webhook_params = {"user.name": user_name, "user.id": user_content["user_id"],
                      "user.email": user_content["email"], "callback_url": callback_url}
    process_webhook_requests(WebhookAction.CREATE_USER, webhook_params, update_user_status_on_error=True)

    return ax.valid_http(http_success=HTTPCreated, detail=s.Users_POST_CreatedResponseSchema.description,
                         content={"user": user_content})


def update_user(user, request, new_user_name=None, new_password=None, new_email=None, new_status=None):
    # type: (models.User, Request, Optional[Str], Optional[Str], Optional[Str], Optional[models.UserStatuses]) -> None
    """
    Applies updates of user details with specified values after validation.

    :param user: targeted user to update .
    :param request: request that produced this update operation.
    :param new_user_name: new name to apply (if provided).
    :param new_password: new password to apply (if provided).
    :param new_email: new email to apply (if provided).
    :param new_status: new status to apply (if provided).
    :return: None if update was successful.
    """
    update_username = new_user_name is not None and not compare_digest(user.user_name, str(new_user_name))
    update_password = new_password is not None and not compare_digest(user.user_password, str(new_password))
    update_email = new_email is not None and not compare_digest(user.email, str(new_email))
    update_status = new_status is not None and models.UserStatuses.get(user.status) != new_status
    ax.verify_param(any([update_username, update_password, update_email, update_status]), is_true=True,
                    with_param=False,  # params are not useful in response for this case
                    content={"user_name": user.user_name},
                    http_error=HTTPBadRequest, msg_on_fail=s.User_PATCH_BadRequestResponseSchema.description)

    # FIXME: disable email edit when self-registration is enabled to avoid not having any confirmation of new email
    #   (see https://github.com/Ouranosinc/Magpie/issues/436)
    update_email_admin_only = False
    if update_email:
        update_email_admin_only = asbool(get_constant("MAGPIE_USER_REGISTRATION_ENABLED", request,
                                                      default_value=False, print_missing=True,
                                                      raise_missing=False, raise_not_set=False))

    # user name/status change is admin-only operation
    if update_username or update_status or update_email_admin_only:
        err_msg = s.User_PATCH_ForbiddenResponseSchema.description
        if update_email_admin_only and not (update_username or update_status):
            err_msg = "User email update not permitted by non-administrators when email registration is enabled."
        ax.verify_param(get_constant("MAGPIE_ADMIN_GROUP", request), is_in=True,
                        param_compare=get_user_groups_checked(request.user, request.db), with_param=False,
                        http_error=HTTPForbidden, msg_on_fail=err_msg)

    # logged user updating itself is forbidden if it corresponds to special users
    # cannot edit reserved keywords nor apply them to another user
    forbidden_user_names = [
        get_constant("MAGPIE_ADMIN_USER", request),
        get_constant("MAGPIE_ANONYMOUS_USER", request),
        get_constant("MAGPIE_LOGGED_USER", request),
    ]
    check_user_name_cases = [user.user_name, new_user_name] if update_username else [user.user_name]
    for check_user_name in check_user_name_cases:
        ax.verify_param(check_user_name, not_in=True, param_compare=forbidden_user_names,
                        param_name="user_name", with_param=False,  # don't leak the user names
                        http_error=HTTPForbidden, content={"user_name": str(check_user_name)},
                        msg_on_fail=s.User_PATCH_ForbiddenResponseSchema.description)
    if update_username:
        check_user_info(user_name=new_user_name, check_email=False, check_password=False, check_group=False)
        existing_user = ax.evaluate_call(lambda: UserService.by_user_name(new_user_name, db_session=request.db),
                                         fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                         msg_on_fail=s.User_PATCH_ForbiddenResponseSchema.description)
        ax.verify_param(existing_user, is_none=True, with_param=False, http_error=HTTPConflict,
                        msg_on_fail=s.User_PATCH_ConflictResponseSchema.description)
        user.user_name = new_user_name
    if update_email:
        check_user_info(email=new_email, check_name=False, check_password=False, check_group=False)
        user.email = new_email
    if update_password:
        check_user_info(password=new_password, check_name=False, check_email=False, check_group=False)
        UserService.set_password(user, new_password)
        UserService.regenerate_security_code(user)
    if update_status:
        ax.verify_param(new_status, is_in=True, param_compare=s.UserStatuses.values(), param_name="status",
                        msg_on_fail=s.User_Check_Status_BadRequestResponseSchema.description, http_error=HTTPBadRequest)
        user.status = new_status
        callback_url = generate_callback_url(models.TokenOperation.WEBHOOK_USER_STATUS_ERROR, request.db, user=user)
        webhook_params = {"user.name": user.user_name, "user.id": user.id,
                          "user.status": user.status, "callback_url": callback_url}
        # force commit before webhook requests, so that the user's status can be reverted if a webhook error occurs
        transaction.commit()
        process_webhook_requests(WebhookAction.UPDATE_USER_STATUS, webhook_params)


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

    new_perm = models.UserResourcePermission(resource_id=res_id, user_id=user.id, perm_name=str(permission))  # noqa
    ax.verify_param(new_perm, not_none=True, http_error=HTTPForbidden,
                    content={"resource_id": res_id, "user_id": user.id},
                    msg_on_fail=s.UserResourcePermissions_POST_ForbiddenResponseSchema.description)
    ax.evaluate_call(lambda: db_session.add(new_perm), fallback=lambda: db_session.rollback(),
                     http_error=HTTPForbidden, content=err_content,
                     msg_on_fail=s.UserResourcePermissions_POST_ForbiddenResponseSchema.description)
    webhook_params = get_permission_update_params(user, resource, permission)
    process_webhook_requests(WebhookAction.CREATE_USER_PERMISSION, webhook_params)
    return ax.valid_http(http_success=http_success, content=err_content, detail=http_detail)


def assign_user_group(user, group, db_session):
    # type: (models.User, models.Group, Session) -> None
    """
    Creates a user-group relationship (user membership to a group).

    :returns: nothing - user-group is created.
    :raises HTTPError: corresponding error matching problem encountered.
    """
    ax.verify_param(user.id, param_compare=[usr.id for usr in group.users], not_in=True, with_param=False,
                    http_error=HTTPConflict, content={"user_name": user.user_name, "group_name": group.group_name},
                    msg_on_fail=s.UserGroups_POST_ConflictResponseSchema.description)
    ax.evaluate_call(lambda: db_session.add(models.UserGroup(group_id=group.id, user_id=user.id)),  # noqa
                     fallback=lambda: db_session.rollback(), http_error=HTTPForbidden,
                     msg_on_fail=s.UserGroups_POST_RelationshipForbiddenResponseSchema.description,
                     content={"user_name": user.user_name, "group_name": group.group_name})


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
    webhook_params = get_permission_update_params(user, resource, permission)
    process_webhook_requests(WebhookAction.DELETE_USER_PERMISSION, webhook_params)
    return ax.valid_http(http_success=HTTPOk, detail=s.UserResourcePermissionName_DELETE_OkResponseSchema.description)


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


def get_user_resource_permissions(user,             # type: models.User
                                  resource,         # type: models.Resource
                                  db_session,       # type: Session
                                  inherit=False,    # type: bool
                                  resolve=False,    # type: bool
                                  ):                # type: (...) -> Tuple[List[PermissionSet], PermissionType, bool]
    """
    Retrieves user resource permissions applied directly, with inherited group permissions, or resolve between them.

    :param user: user for which to retrieve permissions for the resource, and optionally its groups as well.
    :param resource: resource for which permissions to retrieve are applied on.
    :param db_session: database session
    :param inherit: obtain permissions with user's group inheritance (duplicate permissions possible across user/groups)
    :param resolve: resolve permissions across user/groups to obtain a single highest priority permission on resource.
    """
    perm_unique = True
    if inherit or resolve:
        perm_unique = resolve  # allow duplicates name/access/scope from distinct groups if not resolved
        res_perm_list = ResourceService.perms_for_user(resource, user, db_session=db_session)
        res_perm_list = regroup_permissions_by_resource(res_perm_list, resolve=resolve)
        res_perm_list = res_perm_list.get(resource.resource_id, [])
        perm_type = PermissionType.INHERITED
    else:
        res_perm_list = ResourceService.direct_perms_for_user(resource, user, db_session=db_session)
        perm_type = PermissionType.DIRECT
    return res_perm_list, perm_type, perm_unique


def get_user_resource_permissions_response(user, resource, request,
                                           inherit_groups_permissions=True,
                                           resolve_groups_permissions=False,
                                           effective_permissions=False):
    # type: (models.User, ServiceOrResourceType, Request, bool, bool, bool) -> HTTPException
    """
    Retrieves user resource permissions with or without inherited group permissions.

    Alternatively retrieves the effective user resource permissions, where group permissions are implied as `True`.

    .. warning::
        Does not consider direct :term:`Resource` ownership.

    .. seealso::
        - :func:`get_direct_inherited_resolved_resource_permissions`
        - :func:`get_user_service_permissions`

    :returns: valid HTTP response on successful operations.
    :raises HTTPException: error HTTP response of corresponding situation.
    """
    db_session = request.db

    def get_usr_res_perms():
        perm_unique = True
        if resource.owner_user_id == user.id:
            # FIXME: no 'magpie.models.Resource.permissions' - ok for now because no owner handling...
            perm_type = PermissionType.OWNED
            res_perm_list = models.RESOURCE_TYPE_DICT[resource.type].permissions
        else:
            if effective_permissions:
                svc = ru.get_resource_root_service_impl(resource, request)
                res_perm_list = svc.effective_permissions(user, resource)
                perm_type = PermissionType.EFFECTIVE
            else:
                res_perm_list, perm_type, perm_unique = get_user_resource_permissions(
                    user, resource, db_session, inherit=inherit_groups_permissions, resolve=resolve_groups_permissions
                )
        return format_permissions(res_perm_list, perm_type, force_unique=perm_unique)

    permissions = ax.evaluate_call(
        lambda: get_usr_res_perms(),
        fallback=lambda: db_session.rollback(), http_error=HTTPInternalServerError,
        msg_on_fail=s.UserResourcePermissions_GET_NotFoundResponseSchema.description,
        content={"resource_name": str(resource.resource_name), "user_name": str(user.user_name)})
    return ax.valid_http(http_success=HTTPOk, content=permissions,
                         detail=s.UserResourcePermissions_GET_OkResponseSchema.description)


def get_user_services(user, request, cascade_resources=False, format_as_list=False,
                      inherit_groups_permissions=False, resolve_groups_permissions=False, service_types=None):
    # type: (models.User, Request, bool, bool, bool, bool, Optional[List[Str]]) -> UserServicesType
    """
    Returns services by type with corresponding services by name containing sub-dict information.

    .. seealso::
        :func:`regroup_permissions_by_resource`

    :param user: user for which to find services
    :param request: request with database session connection
    :param cascade_resources:
        If ``False``, return only services which the :term:`User` has :term:`Immediate Permissions` on specialized
        top-level resources corresponding to a :term:`Service`.
        Otherwise, return every service that has at least one sub-resource with permissions (children at any-level).
        In both cases, the *permissions* looked for consider either only :term:`Direct Permissions` or any
        :term:`Inherited Permissions` according to the value of :paramref:`inherit_groups_permissions`.
    :param inherit_groups_permissions:
        If ``False``, return only user-specific service/sub-resources :term:`Direct Permissions`.
        Otherwise, resolve :term:`Inherited Permissions` using all groups the user is member of.
    :param resolve_groups_permissions:
        Whether to combine :term:`Direct Permissions` and :term:`Inherited Permissions` for respective resources or not.
    :param format_as_list:
        Returns as list of service dict information (not grouped by type and by name)
    :param service_types:
        Filter list of service types for which to return details. All service types are used if omitted.
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
                                                        inherit_groups_permissions=inherit_groups_permissions,
                                                        resolve_groups_permissions=resolve_groups_permissions)
    perm_type = PermissionType.INHERITED if inherit_groups_permissions else PermissionType.DIRECT
    services = {}
    force_service_types = True
    if service_types is None:
        force_service_types = False
        service_types = list(SERVICE_TYPE_DICT)
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
        if svc.service_type not in service_types:
            continue
        if svc.service_type not in services:
            services[svc.service_type] = {}
        svc_name = svc.service.resource_name
        svc_type = svc.service_type

        # if service was not already added, add it (could be directly its permissions, or empty via children resource)
        # otherwise, set explicit immediate permissions on service instead of empty children resource permissions
        if svc_name not in services[svc_type] or is_service:
            svc_json = format_service(svc.service, perms, perm_type, show_private_url=False)
            services[svc_type][svc_name] = svc_json

    # explicitly requested service types will have empty sections if none apply (to make it explicit there is nothing)
    if force_service_types:
        for svc_type in service_types:
            services.setdefault(svc_type, {})

    services = {svc_type: dict(sorted(svc_items.items())) for svc_type, svc_items in sorted(services.items())}
    if not format_as_list:
        return services

    services_list = list()
    for svc_type in services:
        for svc_name in services[svc_type]:
            services_list.append(services[svc_type][svc_name])
    return services_list


def get_user_service_permissions(user, service, request,
                                 inherit_groups_permissions=True, resolve_groups_permissions=False):
    # type: (models.User, models.Service, Request, bool, bool) -> List[PermissionSet]
    """
    Retrieve the permissions the user has directly on a service or inherited permissions by its group memberships.

    .. warning::
        - Does not consider :term:`Effective Permissions` ownership.
        - Considers direct :term:`Service` ownership, but not implemented everywhere (not operational).

    .. seealso::
        - :func:`get_user_resource_permissions`
        - :func:`get_user_resource_permissions_response`
    """
    if service.owner_user_id == user.id:
        perm_type = PermissionType.OWNED
        usr_svc_perms = service_factory(service, request).permissions
    else:
        usr_svc_perms, perm_type, _ = get_user_resource_permissions(
            user, service, request.db, inherit=inherit_groups_permissions, resolve=resolve_groups_permissions
        )
    return [PermissionSet(perm, typ=perm_type) for perm in usr_svc_perms]


def filter_user_permission(resource_permission_list, user):
    # type: (List[PermissionTuple], models.User) -> Iterable[PermissionTuple]
    """
    Retrieves only user :term:`Direct Permissions` amongst a list of user/group resource/service permissions.
    """
    def is_user_perm(perm):
        return perm.group is None and perm.type == "user" and perm.user.user_name == user.user_name
    return filter(is_user_perm, resource_permission_list)


def resolve_user_group_permissions(resource_permission_list):
    # type: (List[ResolvablePermissionType]) -> Iterable[PermissionSet]
    """
    Reduces overlapping user :term:`Inherited Permissions` for corresponding resources/services amongst the given list.

    User :term:`Direct Permissions` have the top-most priority and are therefore selected first if permissions are
    found for corresponding resource. In such case, only one entry is possible (it is invalid to have more than one
    combination of ``(User, Resource, Permission)``, including modifiers, as per validation during their creation).

    Otherwise, for corresponding :term:`Inherited Permissions`, resolve the prioritized permission across every group.
    Similarly to users, :func:`magpie.groups.group_utils.get_similar_group_resource_permission` validate that only one
    combination of ``(Group, Resource, Permission)`` can exist including permission modifiers. Only, cross-group
    memberships for a given resource must then be computed.

    Priority of combined *group-only* permissions follows 3 conditions:
        1. Permissions inherited from special group :py:data:`MAGPIE_ANONYMOUS_GROUP` have lower priority than any
           other more explicit group membership, regardless of permission modifiers applied on it.
        2. Permissions of same group priority with :attr:`Access.DENY` are prioritized over :attr:`Access.ALLOW`.
        3. Permissions of same group priority with :attr:`Scope.RECURSIVE` are prioritized over :attr:`Access.MATCH` as
           they affect a larger range of resources when :term:`Effective Permissions` are eventually requested.

    .. note::
        Resource tree inherited resolution is not considered here (no recursive :term:`Effective Permissions` computed).
        Only same-level scope of every given resource is processed independently. The intended behaviour here is
        therefore to help illustrate in responses *how deep* is a given permission going to have an impact onto
        lower-level resources, making :attr:`Scope.RECURSIVE` more important than specific instance :attr:`Scope.MATCH`.

    .. seealso::
        - Sorting methods of :class:`magpie.permissions.PermissionSet` that orders the permissions with desired result.
        - :func:`magpie.groups.group_utils.get_similar_group_resource_permission`
        - :func:`magpie.users.user_utils.get_similar_user_resource_permission`
    """
    # convert all first to avoid re-doing it each iteration for comparisons
    res_perm_sets = [PermissionSet(perm) for perm in resource_permission_list]

    # quickly return if there are no conflict to resolve
    res_perms = [(perm.perm_tuple.resource.resource_id, perm.name) for perm in res_perm_sets]
    if len(set(res_perms)) == len(res_perms):
        return res_perm_sets

    # combine overlapping resource/permission
    combo_perms = {}
    for perm in res_perm_sets:
        res_id = perm.perm_tuple.resource.resource_id
        perm_key = (res_id, perm.name)
        prev_perm = combo_perms.get(perm_key)
        if not prev_perm:
            combo_perms[perm_key] = perm
            continue
        combo_perms[perm_key] = PermissionSet.resolve(perm, prev_perm)
    return list(combo_perms.values())


def regroup_permissions_by_resource(resource_permissions, resolve=False):
    # type: (Iterable[ResolvablePermissionType], bool) -> ResourcePermissionMap
    """
    Regroups multiple uncategorized permissions into a dictionary of corresponding resource IDs.

    While regrouping the various permissions (both :term:`Direct Permissions` and any amount of groups
    :term:`Inherited Permissions`) under their respective resource by ID, optionally resolve overlapping or conflicting
    permissions by name such that only one permission persists for that resource and name.

    .. seealso::
        :func:`resolve_user_group_permissions`

    :param resource_permissions:
        List of resource permissions to process.
        Can include both user :term:`Direct Permissions` and its groups :term:`Inherited Permissions`.
    :param resolve:
        When ``False``, only mapping by resource ID is accomplished. Full listing of permissions is returned.
        Otherwise, resolves the corresponding resource permissions (by same ID) considering various priority rules to
        obtain unique permission names per resource.
    :return: resolved permission
    """

    # regroup by resource
    resources_permissions_dict = {}
    for res_perm in resource_permissions:
        res_perm = PermissionSet(res_perm)
        res_id = res_perm.perm_tuple.resource.resource_id
        if res_id not in resources_permissions_dict:
            resources_permissions_dict[res_id] = [res_perm]
        else:
            resources_permissions_dict[res_id].append(res_perm)

    # remove any duplicates that could be incorporated by multiple groups as requested
    if resolve:
        for res_id in resources_permissions_dict:
            resources_permissions_dict[res_id] = resolve_user_group_permissions(resources_permissions_dict[res_id])
    return resources_permissions_dict


def get_user_resources_permissions_dict(user, request, resource_types=None, resource_ids=None,
                                        inherit_groups_permissions=True, resolve_groups_permissions=False):
    # type: (models.User, Request, Optional[List[Str]], Optional[List[int]], bool, bool) -> ResourcePermissionMap
    """
    Creates a dictionary of resources ID with corresponding permissions of the user.

    .. seealso::
        :func:`regroup_permissions_by_resource`

    :param user: user for which to find resources permissions
    :param request: request with database session connection
    :param resource_types: filter the search query with only the specified resource types
    :param resource_ids: filter the search query to only the specified resource IDs
    :param inherit_groups_permissions:
        Whether to include group inherited permissions from user memberships or not.
        If ``False``, return only user-specific resource permissions.
        Otherwise, resolve inherited permissions using all groups the user is member of.
    :param resolve_groups_permissions: whether to combine corresponding user/group permissions into one or not.
    :return:
        Only resources which the user has permissions on, or including all :term:`Inherited Permissions`, according to
        :paramref:`inherit_groups_permissions` argument.
    """
    ax.verify_param(user, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.UserResourcePermissions_GET_NotFoundResponseSchema.description)

    # full list of user/groups permissions, filter afterwards according to flags
    res_perm_tuple_list = UserService.resources_with_possible_perms(
        user, resource_ids=resource_ids, resource_types=resource_types, db_session=request.db)
    if not inherit_groups_permissions and not resolve_groups_permissions:
        res_perm_tuple_list = filter_user_permission(res_perm_tuple_list, user)
    return regroup_permissions_by_resource(res_perm_tuple_list, resolve=resolve_groups_permissions)


def get_user_service_resources_permissions_dict(user, service, request,
                                                inherit_groups_permissions=True, resolve_groups_permissions=False):
    # type: (models.User, models.Service, Request, bool, bool) -> ResourcePermissionMap
    """
    Retrieves all permissions the user has for every :term:`Resource` nested under the :term:`Service`.

    The retrieved permissions can either include only :term:`Direct Permissions` or a combination of user and group
    :term:`Inherited Permissions` accordingly to provided options.

    .. seealso::
        :func:`get_user_resources_permissions_dict`
        :func:`regroup_permissions_by_resource`

    :returns: dictionary of resource IDs with corresponding permissions.
    """
    resources_under_service = models.RESOURCE_TREE_SERVICE.from_parent_deeper(parent_id=service.resource_id,
                                                                              db_session=request.db)
    resource_ids = [resource.Resource.resource_id for resource in resources_under_service]
    if not resource_ids:
        return {}  # return immediately, otherwise empty list generates dict of all existing resources (i.e. no-filter)
    return get_user_resources_permissions_dict(user, request, resource_types=None, resource_ids=resource_ids,
                                               inherit_groups_permissions=inherit_groups_permissions,
                                               resolve_groups_permissions=resolve_groups_permissions)


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
