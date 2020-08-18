from authomatic.adapters import WebObAdapter
from authomatic.core import Credentials, LoginResult, resolve_provider_class
from authomatic.exceptions import OAuth2Error
from pyramid.authentication import Authenticated
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPException,
    HTTPForbidden,
    HTTPFound,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPOk,
    HTTPTemporaryRedirect,
    HTTPUnauthorized
)
from pyramid.request import Request
from pyramid.response import Response
from pyramid.security import NO_PERMISSION_REQUIRED, forget, remember
from pyramid.view import view_config
from six.moves.urllib.parse import urlparse
from ziggurat_foundations.ext.pyramid.sign_in import ZigguratSignInBadAuth, ZigguratSignInSuccess, ZigguratSignOut
from ziggurat_foundations.models.services.external_identity import ExternalIdentityService
from ziggurat_foundations.models.services.user import UserService

from magpie import models
from magpie.api import exception as ax
from magpie.api import generic as ag
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.user.user_formats import format_user
from magpie.api.management.user.user_utils import create_user
from magpie.constants import get_constant
from magpie.security import authomatic_setup, get_provider_names
from magpie.utils import CONTENT_TYPE_JSON, convert_response, get_logger, get_magpie_url

LOGGER = get_logger(__name__)


# dictionaries of {'provider_id': 'provider_display_name'}
MAGPIE_DEFAULT_PROVIDER = get_constant("MAGPIE_DEFAULT_PROVIDER")
MAGPIE_INTERNAL_PROVIDERS = {MAGPIE_DEFAULT_PROVIDER: MAGPIE_DEFAULT_PROVIDER.capitalize()}
MAGPIE_EXTERNAL_PROVIDERS = get_provider_names()
MAGPIE_PROVIDER_KEYS = list(MAGPIE_INTERNAL_PROVIDERS.keys()) + list(MAGPIE_EXTERNAL_PROVIDERS.keys())


# FIXME: use provider enum
def process_sign_in_external(request, username, provider):
    provider_name = provider.lower()
    if provider_name == "openid":
        query_field = dict(id=username)
    elif provider_name == "github":
        query_field = None
        # query_field = dict(login_field=username)
    elif provider_name == "wso2":
        query_field = {}
    else:
        query_field = dict(username=username)

    came_from = request.POST.get("came_from", "/")
    request.response.set_cookie("homepage_route", came_from)
    external_login_route = request.route_url(s.ProviderSigninAPI.name, provider_name=provider_name, _query=query_field)
    return HTTPTemporaryRedirect(location=external_login_route, headers=request.response.headers)


def verify_provider(provider_name):
    ax.verify_param(provider_name, param_name="provider_name", param_compare=MAGPIE_PROVIDER_KEYS, is_in=True,
                    http_error=HTTPNotFound, msg_on_fail=s.ProviderSignin_GET_NotFoundResponseSchema.description)


@s.SigninAPI.post(schema=s.Signin_POST_RequestSchema(), tags=[s.LoginTag], response_schemas=s.Signin_POST_responses)
@view_config(route_name=s.SigninAPI.name, request_method="POST", permission=NO_PERMISSION_REQUIRED)
def sign_in(request):
    """
    Signs in a user session.
    """
    provider_name = ar.get_value_multiformat_body_checked(request, "provider_name", default=MAGPIE_DEFAULT_PROVIDER)
    provider_name = provider_name.lower()
    # magpie supports login from both username or corresponding email
    # therefore validate pattern combination manually after fetch otherwise email format fails patter match
    user_name = ar.get_value_multiformat_body_checked(request, "user_name", pattern=None)
    pattern = ax.EMAIL_REGEX if "@" in user_name else ax.PARAM_REGEX
    ax.verify_param(user_name, matches=True, param_compare=pattern, param_name="user_name",
                    http_error=HTTPBadRequest, msg_on_fail=s.BadRequestResponseSchema.description)
    password = ar.get_multiformat_body(request, "password")   # no check since password is None for external login
    verify_provider(provider_name)

    if provider_name in MAGPIE_INTERNAL_PROVIDERS.keys():
        # obtain the raw path, without any '/magpie' prefix (if any), let 'application_url' handle it
        signin_internal_path = request.route_url("ziggurat.routes.sign_in", _app_url="")
        signin_internal_data = {"user_name": user_name, "password": password, "provider_name": provider_name}
        signin_sub_request = Request.blank(signin_internal_path, base_url=request.application_url,
                                           headers={"Accept": CONTENT_TYPE_JSON}, POST=signin_internal_data)
        signin_response = request.invoke_subrequest(signin_sub_request, use_tweens=True)
        if signin_response.status_code == HTTPOk.code:
            return convert_response(signin_response)
        login_failure(request, s.Signin_POST_UnauthorizedResponseSchema.description)

    elif provider_name in MAGPIE_EXTERNAL_PROVIDERS.keys():
        return ax.evaluate_call(lambda: process_sign_in_external(request, user_name, provider_name),
                                http_error=HTTPInternalServerError,
                                content={"user_name": user_name, "provider_name": provider_name},
                                msg_on_fail=s.Signin_POST_External_InternalServerErrorResponseSchema.description)


@view_config(context=ZigguratSignInSuccess, permission=NO_PERMISSION_REQUIRED)
def login_success_ziggurat(request):
    """Response from redirect upon successful login with valid user credentials.

    Header ``Set-Cookie`` from this response will allow creation of the response cookies.

    .. seealso::
        - :func:`sign_in`
    """
    # headers contains login authorization cookie
    return ax.valid_http(http_success=HTTPOk, http_kwargs={"headers": request.context.headers},
                         detail=s.Signin_POST_OkResponseSchema.description)


@view_config(context=ZigguratSignInBadAuth, permission=NO_PERMISSION_REQUIRED)
def login_failure(request, reason=None):
    """Response from redirect upon login failure, either because of invalid or incorrect user credentials.

    .. seealso::
        - :func:`sign_in`
    """
    http_err = HTTPUnauthorized
    if reason is None:
        reason = s.Signin_POST_UnauthorizedResponseSchema.description
        try:
            user_name = ar.get_value_multiformat_body_checked(request, "user_name", default=None)
            ar.get_value_multiformat_body_checked(request, "password", default=None, pattern=None)
        except HTTPException:
            http_err = HTTPBadRequest
            reason = s.Signin_POST_BadRequestResponseSchema.description
        else:
            user_name_list = ax.evaluate_call(
                lambda: [user.user_name for user in UserService.all(models.User, db_session=request.db)],
                fallback=lambda: request.db.rollback(), http_error=HTTPForbidden,
                msg_on_fail=s.Signin_POST_ForbiddenResponseSchema.description)
            if user_name in user_name_list:
                http_err = HTTPInternalServerError
                reason = s.Signin_POST_Internal_InternalServerErrorResponseSchema.description
    content = ag.get_request_info(request, default_message=s.Signin_POST_UnauthorizedResponseSchema.description)
    content.update({"reason": str(reason)})
    ax.raise_http(http_error=http_err, content=content, detail=s.Signin_POST_UnauthorizedResponseSchema.description)


def new_user_external(external_user_name, external_id, email, provider_name, db_session):
    """
    Create new user with an External Identity.
    """
    internal_user_name = external_id + "_" + provider_name
    internal_user_name = internal_user_name.replace(" ", "_")
    group_name = get_constant("MAGPIE_USERS_GROUP")
    create_user(internal_user_name, password=None, email=email, group_name=group_name, db_session=db_session)

    user = UserService.by_user_name(internal_user_name, db_session=db_session)
    ex_identity = models.ExternalIdentity(external_user_name=external_user_name, external_id=external_id,  # noqa
                                          local_user_id=user.id, provider_name=provider_name)  # noqa
    ax.evaluate_call(lambda: db_session.add(ex_identity), fallback=lambda: db_session.rollback(),
                     http_error=HTTPConflict, msg_on_fail=s.Signin_POST_ConflictResponseSchema.description,
                     content={"provider_name": str(provider_name),
                              "internal_user_name": str(internal_user_name),
                              "external_user_name": str(external_user_name),
                              "external_id": str(external_id)})
    user.external_identities.append(ex_identity)
    return user


def login_success_external(request, external_user_name, external_id, email, provider_name):
    # find possibly already registered user by external_id/provider
    user = ExternalIdentityService.user_by_external_id_and_provider(external_id, provider_name, request.db)
    if user is None:
        # create new user with an External Identity
        user = new_user_external(external_user_name=external_user_name, external_id=external_id,
                                 email=email, provider_name=provider_name, db_session=request.db)
    # set a header to remember user (set-cookie)
    headers = remember(request, user.id)

    # redirect to 'Homepage-Route' header only if corresponding to Magpie host
    if "homepage_route" in request.cookies:
        homepage_route = str(request.cookies["homepage_route"])
    elif "Homepage-Route" in request.headers:
        homepage_route = str(request.headers["Homepage-Route"])
    else:
        homepage_route = "/"
    header_host = urlparse(homepage_route).hostname
    magpie_host = get_magpie_url(request)
    if header_host and header_host != magpie_host:
        ax.raise_http(http_error=HTTPForbidden, detail=s.ProviderSignin_GET_ForbiddenResponseSchema.description)
    if not header_host:
        homepage_route = magpie_host + ("/" if not homepage_route.startswith("/") else "") + homepage_route
    return ax.valid_http(http_success=HTTPFound, detail=s.ProviderSignin_GET_FoundResponseSchema.description,
                         content={"homepage_route": homepage_route},
                         http_kwargs={"location": homepage_route, "headers": headers})


@s.ProviderSigninAPI.get(schema=s.ProviderSignin_GET_RequestSchema, tags=[s.LoginTag],
                         response_schemas=s.ProviderSignin_GET_responses)
@view_config(route_name=s.ProviderSigninAPI.name, permission=NO_PERMISSION_REQUIRED)
def authomatic_login(request):
    """
    Signs in a user session using an external provider.
    """

    provider_name = request.matchdict.get("provider_name", "").lower()
    response = Response()
    verify_provider(provider_name)
    try:
        authomatic_handler = authomatic_setup(request)

        # if we directly have the Authorization header, bypass authomatic login and retrieve 'userinfo' to signin
        if "Authorization" in request.headers and "authomatic" not in request.cookies:
            provider_config = authomatic_handler.config.get(provider_name, {})
            provider_class = resolve_provider_class(provider_config.get("class_"))
            provider = provider_class(authomatic_handler, adapter=None, provider_name=provider_name)
            # provide the token user data, let the external provider update it on login afterwards
            token_type, access_token = request.headers.get("Authorization").split()
            data = {"access_token": access_token, "token_type": token_type}
            cred = Credentials(authomatic_handler.config, token=access_token, token_type=token_type, provider=provider)
            provider.credentials = cred
            result = LoginResult(provider)
            # pylint: disable=W0212
            result.provider.user = result.provider._update_or_create_user(data, credentials=cred)  # noqa: W0212

        # otherwise, use the standard login procedure
        else:
            result = authomatic_handler.login(WebObAdapter(request, response), provider_name)
            if result is None:
                if response.location is not None:
                    return HTTPTemporaryRedirect(location=response.location, headers=response.headers)
                return response

        if result:
            if result.error:
                # Login procedure finished with an error.
                error = result.error.to_dict() if hasattr(result.error, "to_dict") else result.error
                LOGGER.debug("Login failure with error. [%r]", error)
                return login_failure(request, reason=result.error.message)
            if result.user:
                # OAuth 2.0 and OAuth 1.0a provide only limited user data on login,
                # update the user to get more info.
                if not (result.user.name and result.user.id):
                    try:
                        response = result.user.update()
                    # this error can happen if providing incorrectly formed authorization header
                    except OAuth2Error as exc:
                        LOGGER.debug("Login failure with Authorization header.")
                        ax.raise_http(http_error=HTTPBadRequest, content={"reason": str(exc.message)},
                                      detail=s.ProviderSignin_GET_BadRequestResponseSchema.description)
                    # verify that the update procedure succeeded with provided token
                    if 400 <= response.status < 500:
                        LOGGER.debug("Login failure with invalid token.")
                        ax.raise_http(http_error=HTTPUnauthorized,
                                      detail=s.ProviderSignin_GET_UnauthorizedResponseSchema.description)
                # create/retrieve the user using found details from login provider
                return login_success_external(request,
                                              external_id=result.user.username or result.user.id,
                                              email=result.user.email,
                                              provider_name=result.provider.name,
                                              external_user_name=result.user.name)
    except Exception as exc:
        exc_msg = "Unhandled error during external provider '{}' login. [{!s}]".format(provider_name, exc)
        LOGGER.exception(exc_msg, exc_info=True)
        ax.raise_http(http_error=HTTPInternalServerError, detail=exc_msg)

    LOGGER.debug("Reached end of login function. Response: %r", response)
    return response


@s.SignoutAPI.get(tags=[s.LoginTag], response_schemas=s.Signout_GET_responses)
@view_config(context=ZigguratSignOut, permission=NO_PERMISSION_REQUIRED)
def sign_out(request):
    """
    Signs out the current user session.
    """
    return ax.valid_http(http_success=HTTPOk, http_kwargs={"headers": forget(request)},
                         detail=s.Signout_GET_OkResponseSchema.description)


@s.SessionAPI.get(tags=[s.LoginTag], response_schemas=s.Session_GET_responses)
@view_config(route_name=s.SessionAPI.name, permission=NO_PERMISSION_REQUIRED)
def get_session(request):
    """
    Get information about current session.
    """
    def _get_session(req):
        principals = ar.get_principals(req)
        if Authenticated in principals:
            user = request.user
            json_resp = {"authenticated": True, "user": format_user(user)}
        else:
            json_resp = {"authenticated": False}
        return json_resp

    session_json = ax.evaluate_call(lambda: _get_session(request), http_error=HTTPInternalServerError,
                                    msg_on_fail=s.Session_GET_InternalServerErrorResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.Session_GET_OkResponseSchema.description, content=session_json)


@s.ProvidersAPI.get(tags=[s.LoginTag], response_schemas=s.Providers_GET_responses)
@view_config(route_name=s.ProvidersAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_providers(request):     # noqa: F811
    """
    Get list of login providers.
    """
    return ax.valid_http(http_success=HTTPOk, detail=s.Providers_GET_OkResponseSchema.description,
                         content={"providers": {"internal": sorted(MAGPIE_INTERNAL_PROVIDERS.values()),
                                                "external": sorted(MAGPIE_EXTERNAL_PROVIDERS.values()), }})
