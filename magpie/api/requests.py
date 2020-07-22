from typing import TYPE_CHECKING

from pyramid.authentication import IAuthenticationPolicy
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
from magpie.api import schemas as s
from magpie.api.exception import evaluate_call, verify_param
from magpie.constants import get_constant
from magpie.utils import CONTENT_TYPE_JSON

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from pyramid.request import Request
    from magpie.typedefs import Any, AnySettingsContainer, Str, Optional, ServiceOrResourceType  # noqa: F401
    from magpie.permissions import Permission  # noqa: F401


def get_request_method_content(request):
    # 'request' object stores GET content into 'GET' property, while other methods are in 'POST' property
    method_property = "GET" if request.method == "GET" else "POST"
    return getattr(request, method_property)


def get_multiformat_any(request, key, default=None):
    # type: (Request, Str, Optional[Any]) -> Any
    """
    Obtains the :paramref:`key` element from the request body using found `Content-Type` header.
    """
    msg = "Key '{key}' could not be extracted from '{method}' of type '{type}'" \
          .format(key=repr(key), method=request.method, type=request.content_type)
    if request.content_type == CONTENT_TYPE_JSON:
        # avoid json parse error if body is empty
        if not len(request.body):
            return default
        return evaluate_call(lambda: request.json.get(key, default),
                             http_error=HTTPInternalServerError, msg_on_fail=msg)
    return evaluate_call(lambda: get_request_method_content(request).get(key, default),
                         http_error=HTTPInternalServerError, msg_on_fail=msg)


def get_multiformat_post(request, key, default=None):
    return get_multiformat_any(request, key, default)


def get_multiformat_put(request, key, default=None):
    return get_multiformat_any(request, key, default)


def get_multiformat_delete(request, key, default=None):
    return get_multiformat_any(request, key, default)


def get_permission_multiformat_post_checked(request, service_or_resource, permission_name_key="permission_name"):
    # type: (Request, ServiceOrResourceType, Str) -> Permission
    """
    Retrieves the permission from the body and validates that it is allowed for the specified `service` or `resource`.
    """
    # import here to avoid circular import error with undefined functions between (api_request, resource_utils)
    from magpie.api.management.resource.resource_utils import check_valid_service_or_resource_permission
    perm_name = get_value_multiformat_post_checked(request, permission_name_key)
    return check_valid_service_or_resource_permission(perm_name, service_or_resource, request.db)


def get_value_multiformat_post_checked(request, key, default=None):
    val = get_multiformat_any(request, key, default=default)
    verify_param(val, not_none=True, not_empty=True, http_error=HTTPUnprocessableEntity,
                 param_name=key, msg_on_fail=s.UnprocessableEntityResponseSchema.description)
    return val


def get_user(request, user_name_or_token=None):
    # type: (Request, Optional[Str]) -> models.User
    """
    Obtains the user corresponding to the provided user-name, token or via lookup of the logged user request session.

    :param request: request from which to obtain application settings and session user as applicable.
    :param user_name_or_token: reference value to employ for lookup of the user.
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
        anonymous = evaluate_call(lambda: UserService.by_user_name(anonymous_user, db_session=request.db),
                                  fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                                  msg_on_fail=s.User_CheckAnonymous_ForbiddenResponseSchema.description)
        verify_param(anonymous, not_none=True, http_error=HTTPNotFound,
                     msg_on_fail=s.User_CheckAnonymous_NotFoundResponseSchema.description)
        return anonymous

    authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
    principals = authn_policy.effective_principals(request)
    admin_group_name = get_constant("MAGPIE_ADMIN_GROUP", settings_container=request)
    admin_group = GroupService.by_group_name(admin_group_name, db_session=request.db)
    admin_principal = "group:{}".format(admin_group.id)
    if admin_principal not in principals:
        raise HTTPForbidden()
    user = evaluate_call(lambda: UserService.by_user_name(user_name_or_token, db_session=request.db),
                         fallback=lambda: request.db.rollback(),
                         http_error=HTTPForbidden, msg_on_fail=s.User_GET_ForbiddenResponseSchema.description)
    verify_param(user, not_none=True, http_error=HTTPNotFound,
                 msg_on_fail=s.User_GET_NotFoundResponseSchema.description)
    return user


def get_user_matchdict_checked_or_logged(request, user_name_key="user_name"):
    # type: (Request, Str) -> models.User
    logged_user_name = get_constant("MAGPIE_LOGGED_USER", settings_container=request)
    logged_user_path = s.UserAPI.path.replace("{" + user_name_key + "}", logged_user_name)
    if user_name_key not in request.matchdict and request.path_info.startswith(logged_user_path):
        return get_user(request, logged_user_name)
    return get_user_matchdict_checked(request, user_name_key)


def get_user_matchdict_checked(request, user_name_key="user_name"):
    # type: (Request, Str) -> models.User
    """Obtains the user matched against the specified request path variable.

    :returns: found user.
    :raises HTTPForbidden: if the requesting user does not have sufficient permission to execute this request.
    :raises HTTPNotFound: if the specified user name or token does not correspond to any existing user.
    """
    user_name = get_value_matchdict_checked(request, user_name_key)
    return get_user(request, user_name)


def get_group_matchdict_checked(request, group_name_key="group_name"):
    # type: (Request, Str) -> models.Group
    """Obtains the group matched against the specified request path variable.

    :returns: found group.
    :raises HTTPForbidden: if the requesting user does not have sufficient permission to execute this request.
    :raises HTTPNotFound: if the specified group name does not correspond to any existing group.
    """
    group_name = get_value_matchdict_checked(request, group_name_key)
    group = evaluate_call(lambda: GroupService.by_group_name(group_name, db_session=request.db),
                          fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                          msg_on_fail=s.Group_MatchDictCheck_ForbiddenResponseSchema.description)
    verify_param(group, not_none=True, http_error=HTTPNotFound,
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
    resource_id = get_value_matchdict_checked(request, resource_name_key)
    resource_id = evaluate_call(lambda: int(resource_id), http_error=HTTPBadRequest,
                                msg_on_fail=s.Resource_MatchDictCheck_BadRequestResponseSchema.description)
    resource = evaluate_call(lambda: ResourceService.by_resource_id(resource_id, db_session=request.db),
                             fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                             msg_on_fail=s.Resource_MatchDictCheck_ForbiddenResponseSchema.description)
    verify_param(resource, not_none=True, http_error=HTTPNotFound,
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
    service = evaluate_call(lambda: models.Service.by_service_name(service_name, db_session=request.db),
                            fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                            msg_on_fail=s.Service_MatchDictCheck_ForbiddenResponseSchema.description)
    verify_param(service, not_none=True, http_error=HTTPNotFound, content={u"service_name": service_name},
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


def get_value_matchdict_checked(request, key):
    # type: (Request, Str) -> Str
    """
    Obtains the matched value located at the expected position of the specified path variable.

    :param request: request from which to retrieve the key.
    :param key: path variable key.
    :return: matched path variable value.
    :raises HTTPUnprocessableEntity: if the key is not an applicable path variable for this request.
    """
    val = request.matchdict.get(key)
    verify_param(val, not_none=True, not_empty=True, http_error=HTTPUnprocessableEntity,
                 param_name=key, msg_on_fail=s.UnprocessableEntityResponseSchema.description)
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
