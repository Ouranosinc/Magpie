from typing import TYPE_CHECKING

import six
from pyramid.authentication import Authenticated, IAuthenticationPolicy
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPForbidden,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPUnprocessableEntity
)
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource import ResourceService
from ziggurat_foundations.models.services.user import UserService

from magpie import models
from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.constants import get_constant
from magpie.utils import CONTENT_TYPE_JSON, get_logger

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from pyramid.request import Request
    from typing import Any, List, Optional, Union
    from magpie.typedefs import AnyAccessPrincipalType, Str, ServiceOrResourceType
    from magpie.permissions import Permission

LOGGER = get_logger(__name__)


def get_request_method_content(request):
    # 'request' object stores GET content into 'GET' property, while other methods are in 'POST' property
    method_property = "GET" if request.method == "GET" else "POST"
    return getattr(request, method_property)


def get_multiformat_body(request, key, default=None):
    # type: (Request, Str, Optional[Any]) -> Any
    """
    Obtains the value of :paramref:`key` element from the request body according to specified `Content-Type` header.

    .. seealso::
        - :func:`get_multiformat_body_checked`
        - :func:`get_permission_multiformat_body_checked`
        - :func:`get_value_multiformat_body_checked`
    """
    msg = "Key '{key}' could not be extracted from '{method}' of type '{type}'" \
          .format(key=repr(key), method=request.method, type=request.content_type)
    if request.content_type == CONTENT_TYPE_JSON:
        # avoid json parse error if body is empty
        if not len(request.body):
            return default
        return ax.evaluate_call(lambda: request.json.get(key, default),
                                http_error=HTTPInternalServerError, msg_on_fail=msg)
    return ax.evaluate_call(lambda: get_request_method_content(request).get(key, default),
                            http_error=HTTPInternalServerError, msg_on_fail=msg)


def get_permission_multiformat_body_checked(request, service_or_resource, permission_name_key="permission_name"):
    # type: (Request, ServiceOrResourceType, Str) -> Permission
    """
    Retrieves the permission from the body and validates that it is allowed for the specified `service` or `resource`.

    Validation combines basic field checks followed by contextual values applicable for the `service` or `resource`.

    .. seealso::
        - :func:`get_value_multiformat_body_checked`
    """
    # import here to avoid circular import error with undefined functions between (api_request, resource_utils)
    from magpie.api.management.resource.resource_utils import check_valid_service_or_resource_permission
    perm_name = get_value_multiformat_body_checked(request, permission_name_key)
    return check_valid_service_or_resource_permission(perm_name, service_or_resource, request.db)


def get_value_multiformat_body_checked(request, key, default=None, check_type=six.string_types, pattern=ax.PARAM_REGEX):
    # type: (Request, Str, Any, Any, Optional[Union[Str, bool]]) -> Str
    """
    Obtains and validates the matched value under :paramref:`key` element from the request body according to
    `Content-Type` header.

    :param request: request from which to retrieve the key.
    :param key: body key variable.
    :param default: value to return instead if not found. If this default is ``None``, it will raise.
    :param check_type: verify that parameter value is of specified type. Set to ``None`` to disable check.
    :param pattern: regex pattern to validate the input with.
        If value evaluates to ``False``, skip this kind of validation (default: :py:data:`ax.PARAM_REGEX`).
    :return: matched path variable value.
    :raises HTTPBadRequest: if the key could not be retrieved from the request body and has no provided default value.
    :raises HTTPUnprocessableEntity: if the retrieved value from the key is invalid for this request.

    .. seealso::
        - :func:`get_multiformat_body`
    """
    val = get_multiformat_body(request, key, default=default)
    ax.verify_param(val, not_none=True, is_type=bool(check_type), param_compare=check_type, param_name=key,
                    http_error=HTTPBadRequest, msg_on_fail=s.BadRequestResponseSchema.description)
    if bool(pattern) and check_type in six.string_types:
        ax.verify_param(val, not_empty=True, matches=True, param_compare=pattern, param_name=key,
                        http_error=HTTPUnprocessableEntity, msg_on_fail=s.UnprocessableEntityResponseSchema.description)
    return val


def get_principals(request):
    # type: (Request) -> List[Str]
    """Obtains the list of effective principals according to detected request session user."""
    authn_policy = request.registry.queryUtility(IAuthenticationPolicy)  # noqa
    principals = authn_policy.effective_principals(request)
    return principals


def get_logged_user(request):
    # type: (Request) -> Optional[models.User]
    try:
        principals = get_principals(request)
        if Authenticated in principals:
            LOGGER.info("User '%s' is authenticated", request.user.user_name)
            return request.user
    except AttributeError:
        pass
    return None


def check_user_has_access(request, access_principals=None):
    # type: (Request, Optional[AnyAccessPrincipalType]) -> bool
    """
    Verifies if the request user has *any* of the specified access principals for the given request.

    Principals can be in the any string of the following form:
        - (int) ``<user-id>``
        - (str) ``group:<group-id>``
        - (str) :py:data:`pyramid.security.Authenticated`
        - (str) :py:data:`pyramid.security.Everyone`
        - (str) ``<custom-scope-string>``

    .. seealso::
        - :py:mod:`ziggurat_foundations.permissions` for details about expected principal values.

    :param request: request for which to evaluate granted user access.
    :param access_principals: none, a single, or many access level principals/scopes.
        If none provided, defaults to :py:data:`magpie.constants.MAGPIE_ADMIN_GROUP` (default application permission).
    :returns: status indicating if user has required access.
    """
    principals = get_principals(request)
    if access_principals is None:
        admin_group_name = get_constant("MAGPIE_ADMIN_GROUP", settings_container=request)
        admin_group = GroupService.by_group_name(admin_group_name, db_session=request.db)
        admin_principal = "group:{}".format(admin_group.id)
        access_principals = [admin_principal]
    if isinstance(access_principals, six.string_types + (int, )):
        access_principals = [access_principals]
    return any(access in principals for access in access_principals)


def get_user(request, user_name_or_token=None, access_principals=None):
    # type: (Request, Optional[Str], Optional[AnyAccessPrincipalType]) -> models.User
    """
    Obtains the user corresponding to the provided user-name, token or via lookup of the logged user request session.

    :param request: request from which to obtain application settings and session user as applicable.
    :param user_name_or_token: reference value to employ for lookup of the user.
    :param access_principals: alternative principals needed by the user doing the request (default admin-level).
    :returns: found user.
    :raises HTTPForbidden: if the requesting user does not have sufficient permission to execute this request.
    :raises HTTPNotFound: if the specified user name or token does not correspond to any existing user.
    """
    logged_user_name = get_constant("MAGPIE_LOGGED_USER", settings_container=request)
    if user_name_or_token is None:
        user_name_or_token = logged_user_name
    if user_name_or_token == logged_user_name:
        curr_user = request.user
        if curr_user:
            return curr_user
        anonymous_user = get_constant("MAGPIE_ANONYMOUS_USER", settings_container=request)
        anonymous = ax.evaluate_call(lambda: UserService.by_user_name(anonymous_user, db_session=request.db),
                                     fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                     msg_on_fail=s.User_CheckAnonymous_ForbiddenResponseSchema.description)
        ax.verify_param(anonymous, not_none=True, http_error=HTTPNotFound,
                        msg_on_fail=s.User_CheckAnonymous_NotFoundResponseSchema.description)
        return anonymous

    ax.verify_param(user_name_or_token, not_none=True, not_empty=True, matches=True,
                    param_compare=ax.PARAM_REGEX, param_name="user_name",
                    http_error=HTTPBadRequest, msg_on_fail=s.User_Check_BadRequestResponseSchema.description)
    ax.verify_param(check_user_has_access(request, access_principals), is_true=True, with_param=False,
                    http_error=HTTPForbidden, msg_on_fail=s.User_GET_ForbiddenResponseSchema.description)
    user = ax.evaluate_call(lambda: UserService.by_user_name(user_name_or_token, db_session=request.db),
                            fallback=lambda: request.db.rollback(),
                            http_error=HTTPInternalServerError,
                            msg_on_fail=s.User_GET_InternalServerErrorResponseSchema.description)
    ax.verify_param(user, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.User_GET_NotFoundResponseSchema.description)
    return user


def get_user_matchdict_checked_or_logged(request, user_name_key="user_name", access_principals=None):
    # type: (Request, Str, Optional[AnyAccessPrincipalType]) -> models.User
    """
    Obtains either the explicit or logged user specified in the request path variable.

    :returns found user.
    :raises HTTPForbidden: if the requesting user does not have sufficient permission to execute this request.
    :raises HTTPNotFound: if the specified user name or logged user keyword does not correspond to any existing user.
    """
    logged_user_name = get_constant("MAGPIE_LOGGED_USER", settings_container=request)
    logged_user_path = s.UserAPI.path.replace("{" + user_name_key + "}", logged_user_name)
    if user_name_key not in request.matchdict or request.path_info.startswith(logged_user_path):
        return get_user(request, logged_user_name, access_principals=access_principals)
    return get_user_matchdict_checked(request, user_name_key, access_principals=access_principals)


def get_user_matchdict_checked(request, user_name_key="user_name", access_principals=None):
    # type: (Request, Str, Optional[AnyAccessPrincipalType]) -> models.User
    """Obtains the user matched against the specified request path variable.

    :returns: found user.
    :raises HTTPForbidden: if the requesting user does not have sufficient permission to execute this request.
    :raises HTTPNotFound: if the specified user name does not correspond to any existing user.

    .. seealso::
        - :func:`get_value_matchdict_checked`
        - :func:`get_user`
    """
    user_name = get_value_matchdict_checked(request, user_name_key)
    return get_user(request, user_name, access_principals=access_principals)


def get_group_matchdict_checked(request, group_name_key="group_name"):
    # type: (Request, Str) -> models.Group
    """Obtains the group matched against the specified request path variable.

    :returns: found group.
    :raises HTTPForbidden: if the requesting user does not have sufficient permission to execute this request.
    :raises HTTPNotFound: if the specified group name does not correspond to any existing group.
    """
    group_name = get_value_matchdict_checked(request, group_name_key)
    group = ax.evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=request.db),
                             fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                             msg_on_fail=s.Group_MatchDictCheck_ForbiddenResponseSchema.description)
    ax.verify_param(group, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.Group_MatchDictCheck_NotFoundResponseSchema.description)
    return group


def get_resource_matchdict_checked(request, resource_name_key="resource_id"):
    # type: (Request, Str) -> models.Resource
    """
    Obtains the resource matched against the specified request path variable.

    :returns: found resource.
    :raises HTTPForbidden: if the requesting user does not have sufficient permission to execute this request.
    :raises HTTPNotFound: if the specified resource ID does not correspond to any existing resource.
    """
    resource_id = get_value_matchdict_checked(request, resource_name_key, pattern=ax.INDEX_REGEX)
    resource_id = ax.evaluate_call(lambda: int(resource_id), http_error=HTTPBadRequest,
                                   msg_on_fail=s.Resource_MatchDictCheck_BadRequestResponseSchema.description)
    resource = ax.evaluate_call(lambda: ResourceService.by_resource_id(resource_id, db_session=request.db),
                                fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                msg_on_fail=s.Resource_MatchDictCheck_ForbiddenResponseSchema.description)
    ax.verify_param(resource, not_none=True, http_error=HTTPNotFound,
                    msg_on_fail=s.Resource_MatchDictCheck_NotFoundResponseSchema.description)
    return resource


def get_service_matchdict_checked(request, service_name_key="service_name"):
    # type: (Request, Str) -> models.Service
    """
    Obtains the service matched against the specified request path variable.

    :returns: found service.
    :raises HTTPForbidden: if the requesting user does not have sufficient permission to execute this request.
    :raises HTTPNotFound: if the specified service name does not correspond to any existing service.
    """
    service_name = get_value_matchdict_checked(request, service_name_key)
    service = ax.evaluate_call(lambda: models.Service.by_service_name(service_name, db_session=request.db),
                               fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                               msg_on_fail=s.Service_MatchDictCheck_ForbiddenResponseSchema.description)
    ax.verify_param(service, not_none=True, http_error=HTTPNotFound, content={"service_name": service_name},
                    msg_on_fail=s.Service_MatchDictCheck_NotFoundResponseSchema.description)
    return service


def get_permission_matchdict_checked(request, service_or_resource, permission_name_key="permission_name"):
    # type: (Request, models.Resource, Str) -> Permission
    """
    Obtains the permission specified in the request path variable and validates that it is allowed for the specified
    :paramref:`service_or_resource` which can be a `service` or a children `resource`.

    Allowed permissions correspond to the *direct* `service` permissions or restrained permissions of the `resource`
    under its root `service`.

    :returns: found permission name if valid for the service/resource
    """
    # pylint: disable=C0415  # avoid circular import
    from magpie.api.management.resource.resource_utils import check_valid_service_or_resource_permission
    perm_name = get_value_matchdict_checked(request, permission_name_key)
    return check_valid_service_or_resource_permission(perm_name, service_or_resource, request.db)


def get_value_matchdict_checked(request, key, check_type=six.string_types, pattern=ax.PARAM_REGEX):
    # type: (Request, Str, Any, Optional[Union[Str, bool]]) -> Str
    """
    Obtains the matched value located at the expected position of the specified path variable.

    :param request: request from which to retrieve the key.
    :param key: path variable key.
    :param check_type: verify that parameter value is of specified type. Set to ``None`` to disable check.
    :param pattern: regex pattern to validate the input with.
        If value evaluates to ``False``, skip this kind of validation (default: :py:data:`ax.PARAM_REGEX`).
    :return: matched path variable value.
    :raises HTTPUnprocessableEntity: if the key is not an applicable path variable for this request.
    """
    val = request.matchdict.get(key)
    ax.verify_param(val, not_none=True, is_type=bool(check_type), param_compare=check_type, param_name=key,
                    http_error=HTTPUnprocessableEntity, msg_on_fail=s.UnprocessableEntityResponseSchema.description)
    if bool(pattern) and (check_type in six.string_types or check_type == six.string_types):
        ax.verify_param(val, not_empty=True, matches=True, param_name=key, param_compare=pattern,
                        http_error=HTTPUnprocessableEntity, msg_on_fail=s.UnprocessableEntityResponseSchema.description)
    return val


def get_query_param(request, case_insensitive_key, default=None):
    # type: (Request, Str, Optional[Any]) -> Any
    """
    Retrieves a query string value by name (case insensitive), or returns the default if not present.
    """
    for param in request.params:
        if param.lower() == case_insensitive_key:
            return request.params.get(param)
    return default
