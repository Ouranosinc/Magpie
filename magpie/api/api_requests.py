from magpie.api.api_except import evaluate_call, verify_param
from magpie.api import api_rest_schemas as s
from magpie.constants import get_constant
from magpie.definitions import ziggurat_definitions as zig
from magpie.definitions.pyramid_definitions import (
    IAuthenticationPolicy,
    HTTPForbidden,
    HTTPNotFound,
    HTTPNotAcceptable,
    HTTPUnprocessableEntity,
    HTTPInternalServerError,
)
from magpie.utils import CONTENT_TYPE_JSON
from magpie import models
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.pyramid_definitions import Request  # noqa: F401
    from magpie.definitions.typedefs import Any, Str, Optional, ServiceOrResourceType  # noqa: F401
    from magpie.permissions import Permission  # noqa: F401


def get_request_method_content(request):
    # 'request' object stores GET content into 'GET' property, while other methods are in 'POST' property
    method_property = "GET" if request.method == "GET" else "POST"
    return getattr(request, method_property)


def get_multiformat_any(request, key, default=None):
    # type: (Request, Str, Optional[Any]) -> Any
    """Obtains the ``key`` element from the request body using found `Content-Type` header."""
    msg = "Key '{key}' could not be extracted from '{method}' of type '{type}'" \
          .format(key=repr(key), method=request.method, type=request.content_type)
    if request.content_type == CONTENT_TYPE_JSON:
        # avoid json parse error if body is empty
        if not len(request.body):
            return default
        return evaluate_call(lambda: request.json.get(key, default),
                             httpError=HTTPInternalServerError, msgOnFail=msg)
    return evaluate_call(lambda: get_request_method_content(request).get(key, default),
                         httpError=HTTPInternalServerError, msgOnFail=msg)


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
    verify_param(val, notNone=True, notEmpty=True, httpError=HTTPUnprocessableEntity,
                 paramName=key, msgOnFail=s.UnprocessableEntityResponseSchema.description)
    return val


def get_userid_by_token(token, authn_policy):
    cookie_helper = authn_policy.cookie
    cookie = token
    if cookie is None:
        return None
    remote_addr = "0.0.0.0"

    timestamp, userid, tokens, user_data = cookie_helper.parse_ticket(
        cookie_helper.secret,
        cookie,
        remote_addr,
        cookie_helper.hashalg
    )
    return userid


def get_user(request, user_name_or_token):
    if user_name_or_token == get_constant("MAGPIE_LOGGED_USER"):
        curr_user = request.user
        if curr_user:
            return curr_user
        else:
            anonymous_user = get_constant("MAGPIE_ANONYMOUS_USER")
            anonymous = evaluate_call(lambda: zig.UserService.by_user_name(anonymous_user, db_session=request.db),
                                      fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                                      msgOnFail=s.User_CheckAnonymous_ForbiddenResponseSchema.description)
            verify_param(anonymous, notNone=True, httpError=HTTPNotFound,
                         msgOnFail=s.User_CheckAnonymous_NotFoundResponseSchema.description)
            return anonymous
    else:
        authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
        principals = authn_policy.effective_principals(request)
        admin_group = zig.GroupService.by_group_name(get_constant("MAGPIE_ADMIN_GROUP"), db_session=request.db)
        admin_principal = "group:{}".format(admin_group.id)
        if admin_principal not in principals:
            raise HTTPForbidden()
        user = evaluate_call(lambda: zig.UserService.by_user_name(user_name_or_token, db_session=request.db),
                             fallback=lambda: request.db.rollback(),
                             httpError=HTTPForbidden, msgOnFail=s.User_GET_ForbiddenResponseSchema.description)
        verify_param(user, notNone=True, httpError=HTTPNotFound,
                     msgOnFail=s.User_GET_NotFoundResponseSchema.description)
        return user


def get_user_matchdict_checked_or_logged(request, user_name_key="user_name"):
    logged_user_name = get_constant("MAGPIE_LOGGED_USER")
    logged_user_path = s.UserAPI.path.replace("{" + user_name_key + "}", logged_user_name)
    if user_name_key not in request.matchdict and request.path_info.startswith(logged_user_path):
        return get_user(request, logged_user_name)
    return get_user_matchdict_checked(request, user_name_key)


def get_user_matchdict_checked(request, user_name_key="user_name"):
    user_name = get_value_matchdict_checked(request, user_name_key)
    return get_user(request, user_name)


def get_group_matchdict_checked(request, group_name_key="group_name"):
    group_name = get_value_matchdict_checked(request, group_name_key)
    group = evaluate_call(lambda: zig.GroupService.by_group_name(group_name, db_session=request.db),
                          fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                          msgOnFail=s.Group_MatchDictCheck_ForbiddenResponseSchema.description)
    verify_param(group, notNone=True, httpError=HTTPNotFound,
                 msgOnFail=s.Group_MatchDictCheck_NotFoundResponseSchema.description)
    return group


def get_resource_matchdict_checked(request, resource_name_key="resource_id"):
    # type: (Request, Str) -> models.Resource
    resource_id = get_value_matchdict_checked(request, resource_name_key)
    resource_id = evaluate_call(lambda: int(resource_id), httpError=HTTPNotAcceptable,
                                msgOnFail=s.Resource_MatchDictCheck_NotAcceptableResponseSchema.description)
    resource = evaluate_call(lambda: zig.ResourceService.by_resource_id(resource_id, db_session=request.db),
                             fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                             msgOnFail=s.Resource_MatchDictCheck_ForbiddenResponseSchema.description)
    verify_param(resource, notNone=True, httpError=HTTPNotFound,
                 msgOnFail=s.Resource_MatchDictCheck_NotFoundResponseSchema.description)
    return resource


def get_service_matchdict_checked(request, service_name_key="service_name"):
    service_name = get_value_matchdict_checked(request, service_name_key)
    service = evaluate_call(lambda: models.Service.by_service_name(service_name, db_session=request.db),
                            fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                            msgOnFail=s.Service_MatchDictCheck_ForbiddenResponseSchema.description)
    verify_param(service, notNone=True, httpError=HTTPNotFound, content={u'service_name': service_name},
                 msgOnFail=s.Service_MatchDictCheck_NotFoundResponseSchema.description)
    return service


def get_permission_matchdict_checked(request, service_or_resource, permission_name_key="permission_name"):
    # type: (Request, models.Resource, Str) -> Permission
    """
    Obtains the `permission` specified in the ``request`` path and validates that it is allowed for the
    specified ``service_or_resource`` which can be a `service` or a children `resource`.

    Allowed permissions correspond to the direct `service` permissions or restrained permissions of the `resource`
    under its root `service`.

    :returns: found permission name if valid for the service/resource
    """
    # import here to avoid circular import error with undefined functions between (api_request, resource_utils)
    from magpie.api.management.resource.resource_utils import check_valid_service_or_resource_permission
    perm_name = get_value_matchdict_checked(request, permission_name_key)
    return check_valid_service_or_resource_permission(perm_name, service_or_resource, request.db)


def get_value_matchdict_checked(request, key):
    val = request.matchdict.get(key)
    verify_param(val, notNone=True, notEmpty=True, httpError=HTTPUnprocessableEntity,
                 paramName=key, msgOnFail=s.UnprocessableEntityResponseSchema.description)
    return val


def get_query_param(request, case_insensitive_key, default=None):
    # type: (Request, Str, Optional[Any]) -> Any
    """Retrieves a query string value by name (case insensitive), or returns the default if not present."""
    for p in request.params:
        if p.lower() == case_insensitive_key:
            return request.params.get(p)
    return default
