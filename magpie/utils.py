#!/usr/bin/env python
# -*- coding: utf-8 -*-
import inspect
import json
import logging
import os
import sys
import time
import types
from distutils.dir_util import mkpath
from typing import TYPE_CHECKING

import requests
import six
from pyramid.config import ConfigurationError, Configurator
from pyramid.httpexceptions import HTTPClientError, HTTPException, HTTPOk
from pyramid.registry import Registry
from pyramid.request import Request
from pyramid.response import Response
from pyramid.settings import asbool, truthy
from pyramid.threadlocal import get_current_registry
from pyramid_retry import IBeforeRetry, mark_error_retryable
from requests.cookies import RequestsCookieJar
from requests.structures import CaseInsensitiveDict
from six.moves import configparser
from six.moves.urllib.parse import urlparse
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm.exc import DetachedInstanceError
from transaction.interfaces import NoTransaction
from webob.headers import EnvironHeaders, ResponseHeaders
from ziggurat_foundations.models.services.user import UserService

from magpie import __meta__
from magpie.constants import get_constant

if sys.version_info >= (3, 6):
    from enum import Enum
else:
    from aenum import Enum  # noqa

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import _TC  # noqa: E0611,F401,W0212 # pylint: disable=E0611
    from typing import Any, List, NoReturn, Optional, Type, Union

    from pyramid.events import NewRequest
    from pyramid_retry import BeforeRetry

    from magpie import models
    from magpie.typedefs import (
        AnyHeadersType,
        AnyKey,
        AnyResponseType,
        AnySettingsContainer,
        CookiesType,
        HeadersType,
        SettingsType,
        Str
    )

CONTENT_TYPE_ANY = "*/*"
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"
CONTENT_TYPE_HTML = "text/html"
CONTENT_TYPE_PLAIN = "text/plain"
CONTENT_TYPE_APP_XML = "application/xml"
CONTENT_TYPE_TXT_XML = "text/xml"
FORMAT_TYPE_MAPPING = {
    CONTENT_TYPE_JSON: CONTENT_TYPE_JSON,
    CONTENT_TYPE_HTML: CONTENT_TYPE_HTML,
    CONTENT_TYPE_PLAIN: CONTENT_TYPE_PLAIN,
    CONTENT_TYPE_APP_XML: CONTENT_TYPE_APP_XML,
    CONTENT_TYPE_TXT_XML: CONTENT_TYPE_TXT_XML,
    "json": CONTENT_TYPE_JSON,
    "html": CONTENT_TYPE_HTML,
    "text": CONTENT_TYPE_PLAIN,
    "plain": CONTENT_TYPE_PLAIN,
    "xml": CONTENT_TYPE_TXT_XML,
}
SUPPORTED_ACCEPT_TYPES = [
    CONTENT_TYPE_JSON, CONTENT_TYPE_HTML, CONTENT_TYPE_PLAIN, CONTENT_TYPE_APP_XML, CONTENT_TYPE_TXT_XML
]
SUPPORTED_FORMAT_TYPES = list(FORMAT_TYPE_MAPPING.keys())
KNOWN_CONTENT_TYPES = SUPPORTED_ACCEPT_TYPES + [CONTENT_TYPE_FORM, CONTENT_TYPE_ANY]


def get_logger(name, level=None, force_stdout=None, message_format=None, datetime_format=None):
    # type: (Str, Optional[int], bool, Optional[Str], Optional[Str]) -> logging.Logger
    """
    Immediately sets the logger level to avoid duplicate log outputs from the `root logger` and `this logger` when
    `level` is ``logging.NOTSET``.
    """
    logger = logging.getLogger(name)
    if logger.level == logging.NOTSET:
        # use magpie log level if it was specified via ini config with logger sections
        level = level or logging.getLogger("magpie").getEffectiveLevel()
        if not level:
            # pylint: disable=C0415     # avoid circular import
            from magpie.constants import MAGPIE_LOG_LEVEL
            level = MAGPIE_LOG_LEVEL
        logger.setLevel(level)
    if force_stdout or message_format or datetime_format:
        set_logger_config(logger, force_stdout, message_format, datetime_format)
    return logger


LOGGER = get_logger(__name__)


def set_logger_config(logger, force_stdout=False, message_format=None, datetime_format=None, log_file=None):
    # type: (logging.Logger, bool, Optional[Str], Optional[Str], Optional[Str]) -> logging.Logger
    """
    Applies the provided logging configuration settings to the logger.
    """
    if not logger:
        return logger
    handler = None
    formatter = None
    if message_format or datetime_format:
        formatter = logging.Formatter(fmt=message_format, datefmt=datetime_format)
    if force_stdout:
        all_handlers = logging.root.handlers + logger.handlers
        if not any(isinstance(h, logging.StreamHandler) for h in all_handlers):
            handler = logging.StreamHandler(sys.stdout)
            logger.addHandler(handler)  # noqa: type
    if not handler:
        if logger.handlers:
            handler = logger.handlers
        else:
            handler = logging.StreamHandler(sys.stdout)
            logger.addHandler(handler)
    if formatter:
        handler.setFormatter(formatter)
    if log_file:
        all_handlers = logging.root.handlers + logger.handlers
        if not any(isinstance(h, logging.FileHandler) for h in all_handlers):
            handler = logging.FileHandler(log_file)
            if formatter:
                handler.setFormatter(formatter)
            logger.addHandler(handler)
    return logger


def print_log(msg, logger=None, level=logging.INFO, **kwargs):
    # type: (Str, Optional[logging.Logger], int, Any) -> None
    """
    Logs the requested message to the logger and optionally enforce printing to the console according to configuration
    value defined by ``MAGPIE_LOG_PRINT``.
    """
    # pylint: disable=C0415     # cannot use 'get_constant', recursive call
    from magpie.constants import MAGPIE_LOG_PRINT

    if not logger:
        logger = get_logger(__name__)
    if MAGPIE_LOG_PRINT:
        set_logger_config(logger, force_stdout=True)
    if logger.disabled:
        logger.disabled = False
    logger.log(level, msg, **kwargs)


def raise_log(msg, exception=Exception, logger=None, level=logging.ERROR):
    # type: (Str, Type[Exception], Optional[logging.Logger], int) -> NoReturn
    """
    Logs the provided message to the logger and raises the corresponding exception afterwards.

    :raises exception: whichever exception provided is raised systematically after logging.
    """
    if not logger:
        logger = get_logger(__name__)
    logger.log(level, msg)
    if not isclass(exception) or not issubclass(exception, Exception):
        exception = Exception
    raise exception(msg)


def bool2str(value):
    # type: (Any) -> Str
    """
    Converts :paramref:`value` to explicit ``"true"`` or ``"false"`` :class:`str` with permissive variants comparison
    that can represent common falsy or truthy values.
    """
    return "true" if str(value).lower() in truthy else "false"


def islambda(func):
    # type: (Any) -> bool
    """
    Evaluate if argument is a callable :class:`lambda` expression.
    """
    return isinstance(func, types.LambdaType) and func.__name__ == (lambda: None).__name__  # noqa


def isclass(obj):
    # type: (Any) -> bool
    """
    Evaluate an object for :class:`class` type (ie: class definition, not an instance nor any other type).
    """
    return isinstance(obj, (type, six.class_types))


def ismethod(obj):
    # type: (Any) -> bool
    """
    Evaluate an object for :class:`method` type (ie: class method reference.
    """
    if six.PY2:
        return inspect.ismethod(obj)
    return inspect.isroutine(obj) and "." in obj.__qualname__


# alternative to 'makedirs' with 'exists_ok' parameter only available for python>3.5
def make_dirs(path):
    dir_path = os.path.dirname(path)
    if not os.path.isfile(path) or not os.path.isdir(dir_path):
        for subdir in mkpath(dir_path):
            if not os.path.isdir(subdir):
                os.mkdir(subdir)


def get_settings_from_config_ini(config_ini_path, ini_main_section_name="app:magpie_app"):
    parser = configparser.ConfigParser()
    parser.optionxform = lambda option: option  # preserve case of config (ziggurat requires it for 'User' model)
    result = parser.read([config_ini_path])
    # raise silently ignored missing file
    if len(result) != 1 or not os.path.isfile(result[0]):
        if result:
            result = result[0] or os.path.abspath(str(config_ini_path))  # in case not found, use expected location
            message = "Cannot find Magpie INI configuration file [{}] resolved as [{}]".format(config_ini_path, result)
        else:
            message = "Cannot find Magpie INI configuration file [{}]".format(config_ini_path)
        raise ValueError(message)
    settings = dict(parser.items(ini_main_section_name))
    return settings


def setup_cache_settings(settings, force=False, enabled=False, expire=0):
    # type: (SettingsType, bool, bool, int) -> None
    """
    Setup caching settings if not defined in configuration and enforce values if requested.

    Required caching regions that were missing from configuration are initiated with disabled caching by default.
    This ensures that any decorators or region references will not cause unknown key or region errors.

    :param settings: reference to application settings that will be updated in place.
    :param force: enforce following parameters, otherwise only ensure that caching regions exist.
    :param enabled: enable caching when enforced settings is requested.
    :param expire: cache expiration delay if setting values are enforced and enabled.
    """
    if force:
        LOGGER.warning("Enforcing cache settings (enabled=%s, expire=%s)", enabled, expire)

    def _set(key, value):
        if force:
            settings[key] = value
        elif key not in settings:
            LOGGER.warning("Setting missing cache setting (%s=%s)", key, value)
            settings.setdefault(key, value)

    regions = ["acl", "service"]
    _set("cache.regions", ", ".join(regions))
    _set("cache.type", "memory")
    for region in regions:
        cache_region = "cache.{}.enabled".format(region)
        cache_expire = "cache.{}.expire".format(region)
        cache_enable = str(enabled).lower()
        _set(cache_region, cache_enable)
        if asbool(settings[cache_region]):
            _set(cache_expire, str(expire))
        else:
            settings.pop(cache_expire, None)


def setup_session_config(config):
    from magpie.db import get_engine, get_session_factory, get_tm_session

    settings = get_settings(config)

    # avoid sporadic errors session/transaction errors
    #   - sqlalchemy.orm.exc.DetachedInstanceError
    #   - transaction.interfaces.NoTransaction
    # see also:
    #   - https://docs.pylonsproject.org/projects/pyramid_tm/en/latest/
    #   - https://github.com/Pylons/pyramid_tm/issues/74
    #   - https://github.com/Ouranosinc/Magpie/issues/466
    #   - https://github.com/Ouranosinc/Magpie/pull/473
    # Note:
    #   Set value here because both Magpie and Twitcher (via MagpieAdapter.configurator_factory) inherit this setting.
    settings["tm.annotate_user"] = False

    def retry_warn(event):
        # type: (BeforeRetry) -> None
        LOGGER.warning("Will retry request [%s %s] following raised error [%s] during previous attempt.",
                       event.request.method, event.request.url, event.exception)

    # retry sporadic transaction or detached instance errors
    # since these errors happen most of the time during cache reset, following retry should work as intended
    settings.setdefault("retry.attempts", 2)
    config.include("pyramid_retry")
    config.add_subscriber(retry_warn, IBeforeRetry)
    mark_error_retryable(DetachedInstanceError)
    mark_error_retryable(NoTransaction)

    # use 'pyramid_tm' to hook the transaction lifecycle to the request
    # make 'request.db' available for use in Pyramid
    config.include("pyramid_tm")
    session_factory = get_session_factory(get_engine(settings))
    config.registry["dbsession_factory"] = session_factory
    config.add_request_method(
        # 'request.tm' is the transaction manager used by 'pyramid_tm'
        lambda request: get_tm_session(session_factory, request.tm), "db", reify=True
    )

    def debug_request_user(request):
        # type: (Request) -> Optional[models.User]
        """
        Log debug authentication details if requested, and then retrieves the authenticated user.
        """
        debug_cookie_identify(request)
        return get_request_user(request)

    # Register an improved 'request.user' that reattaches the detached session if a transaction commit occurred.
    #   don't use 'reify=True' to ensure the function is called and re-evaluates the detached state
    #   replicate the value substitution optimization offered by 'reify' with an explicit attribute
    settings.setdefault("magpie.debug_cookie_identity", False)
    debug_user = LOGGER.isEnabledFor(logging.DEBUG) and asbool(settings["magpie.debug_cookie_identity"])
    get_user = debug_request_user if debug_user else get_request_user
    config.add_request_method(get_user, "user", reify=False, property=True)


def setup_ziggurat_config(config):
    # type: (Configurator) -> None
    """
    Setup :mod:`ziggurat_foundations` configuration settings and extensions that are required by `Magpie`.

    Ensures that all needed extensions and parameter configuration values are defined as intended.
    Resolves any erroneous configuration or conflicts from the INI (backward compatible to when it was required to
    provide them explicitly) to guarantee that references are defined as needed for the application to behave correctly.

    :param config: configurator reference when loading the web application.
    """
    settings = config.registry.settings
    pyr_incl = "pyramid.includes"
    zig_user = "ziggurat_foundations.ext.pyramid.get_user"
    if pyr_incl in settings and zig_user in settings[pyr_incl]:
        settings[pyr_incl] = settings[pyr_incl].replace("\n" + zig_user, "").replace(zig_user, "")

    settings["ziggurat_foundations.model_locations.User"] = "magpie.models:User"
    settings["ziggurat_foundations.session_provider_callable"] = "magpie.models:get_session_callable"
    settings["ziggurat_foundations.sign_in.username_key"] = "user_name"
    settings["ziggurat_foundations.sign_in.password_key"] = "password"
    settings["ziggurat_foundations.sign_in.came_from_key"] = "came_from"
    settings["ziggurat_foundations.sign_in.sign_in_pattern"] = "/signin_internal"
    settings["ziggurat_foundations.sign_in.sign_out_pattern"] = "/signout"
    config.include("ziggurat_foundations.ext.pyramid.sign_in")


def debug_cookie_identify(request):
    """
    Logs debug information about request cookie.

    .. WARNING::

        This function is intended for debugging purposes only. It reveals sensible configuration information.

    Re-implements basic functionality of :func:`pyramid.AuthTktAuthenticationPolicy.cookie.identify` called via
    :func:`request.unauthenticated_userid` within :func:`get_request_user` to provide additional logging.

    .. seealso::
        - :class:`pyramid.authentication.AuthTktCookieHelper`
        - :class:`pyramid.authentication.AuthTktAuthenticationPolicy`
    """
    # pylint: disable=W0212
    cookie_inst = request._get_authentication_policy().cookie  # noqa: W0212
    cookie = request.cookies.get(cookie_inst.cookie_name)

    LOGGER.debug("Cookie (name: %s, secret: %s, hash-alg: %s) : %s",
                 cookie_inst.cookie_name, cookie_inst.secret, cookie_inst.hashalg, cookie)

    if not cookie:
        LOGGER.debug("No Cookie!")
    else:
        if cookie_inst.include_ip:
            environ = request.environ
            remote_addr = environ["REMOTE_ADDR"]
        else:
            remote_addr = "0.0.0.0"  # nosec # only for log debugging

        LOGGER.debug("Cookie remote addr (include_ip: %s) : %s", cookie_inst.include_ip, remote_addr)
        now = time.time()
        timestamp, _, _, _ = cookie_inst.parse_ticket(cookie_inst.secret, cookie, remote_addr, cookie_inst.hashalg)
        LOGGER.debug("Cookie timestamp: %s, timeout: %s, now: %s", timestamp, cookie_inst.timeout, now)

        if cookie_inst.timeout and ((timestamp + cookie_inst.timeout) < now):
            # the auth_tkt data has expired
            LOGGER.debug("Cookie is expired")

        # Could raise useful exception explaining why unauthenticated_userid is None
        request._get_authentication_policy().cookie.identify(request)  # noqa: W0212


def get_request_user(request):
    # type: (Request) -> Optional[models.User]
    """
    Obtains the user that corresponds to the authentication details found in the request.

    Prior to resolving the user matching the authenticated user ID, reattaches the detached session or closed
    transaction if commit occurred beforehand. This can happen for example when creating a user from a pending-user
    where the user must be committed to allow webhooks to refer to it immediately, although the request has not
    completed processing. Operations using the ``request.user`` reference following that user creation could have a
    detached object state from the session. Also ensure that any resolved user is allow attached to the reestablished
    database session reference in the request.

    After reattaching to the session, following step is the original configuration setup
    similarly to typical methodology::

        config.include("ziggurat_foundations.ext.pyramid.get_user")

    :param request: request to look for authenticated user.
    :return: authenticated user or none if unauthenticated.
    """
    user = getattr(request, "_user_prefetched", None)
    if user is not None and not sa_inspect(user).detached:
        return user
    user_id = request.unauthenticated_userid
    LOGGER.debug("Current user ID is '%s', attempt resolving user...", user_id)

    if user_id is not None:
        user = UserService.by_id(user_id, db_session=request.db)
        LOGGER.debug("Current user has been resolved as '%s'", user)
        if user is None:
            return None
        if sa_inspect(user).detached:
            request.db.merge(user)
        setattr(request, "_user_prefetched", user)
        return user
    return None


def get_json(response):
    """
    Retrieves the 'JSON' body of a response using the property/callable according to the response's implementation.
    """
    if isinstance(response.json, dict):
        return response.json
    return response.json()


def get_header(header_name, header_container, default=None, split=None):
    # type: (Str, AnyHeadersType, Optional[Str], Optional[Union[Str, List[Str]]]) -> Optional[Str]
    """
    Retrieves ``header_name`` by fuzzy match (independently of upper/lower-case and underscore/dash) from various
    framework implementations of ``Headers``.

    If ``split`` is specified, the matched ``header_name`` is first split with it and the first item is returned.
    This allows to parse complex headers (e.g.: ``text/plain; charset=UTF-8`` to ``text/plain`` with ``split=';'``).

    :param header_name: header to find.
    :param header_container: where to look for `header_name`.
    :param default: value to returned if `header_container` is invalid or `header_name` could not be found.
    :param split: character(s) to use to split the *found* `header_name`.
    """
    def fuzzy_name(name):
        return name.lower().replace("-", "_")

    if header_container is None:
        return default
    headers = header_container
    if isinstance(headers, (ResponseHeaders, EnvironHeaders, CaseInsensitiveDict)):
        headers = dict(headers)
    if isinstance(headers, dict):
        headers = header_container.items()
    header_name = fuzzy_name(header_name)
    for h, v in headers:
        if fuzzy_name(h) == header_name:
            if isinstance(split, six.string_types) and len(split) > 1:
                split = [c for c in split]
            if hasattr(split, "__iter__") and not isinstance(split, six.string_types):
                for sep in split:
                    v = v.replace(sep, split[0])
                split = split[0]
            return (v.split(split)[0] if split else v).strip()
    return default


def convert_response(response):
    # type: (AnyResponseType) -> Response
    """
    Converts a :class:`requests.Response` object to an equivalent :class:`pyramid.response.Response` object.

    Content of the :paramref:`response` is expected to be JSON.

    :param response: response to be converted
    :returns: converted response
    """
    if isinstance(response, Response):
        return response
    json_body = get_json(response)
    pyramid_response = Response(body=json_body, headers=response.headers)
    if hasattr(response, "cookies"):
        for cookie in response.cookies:
            pyramid_response.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)  # noqa
    if isinstance(response, HTTPException):
        for header_name, header_value in response.headers._items:  # noqa # pylint: disable=W0212
            if header_name.lower() == "set-cookie":
                pyramid_response.set_cookie(name=header_name, value=header_value, overwrite=True)
    return pyramid_response


def get_authenticate_headers(request, error_type="invalid_token"):
    # type: (Request, Str) -> Optional[HeadersType]
    """
    Obtains all required headers by 401 responses based on executed :paramref:`request`.

    :param request: request that was sent to attempt authentication or access which must respond with Unauthorized.
    :param error_type:
        Additional detail of the cause of error. Must be one of (invalid_request, invalid_token, insufficient_scope).
    """
    # FIXME: support other authentication methods (JWT, HTTP, Basic, Bearer Token, etc.)
    #        in such case, must resolve specified challenge method according to request if provided
    #        (https://github.com/Ouranosinc/Magpie/issues/255)
    # Generic Auth: https://tools.ietf.org/html/rfc7235#section-2.1  (section for schema of 'WWW-Authenticate')
    # Basic/Digest: https://tools.ietf.org/html/rfc2617
    # Bearer Token: https://tools.ietf.org/html/rfc6750
    # Cookie Token: https://tools.ietf.org/id/draft-broyer-http-cookie-auth-00.html#anchor1

    from magpie.api.schemas import SigninAPI  # pylint: disable=C0415

    # avoid adding headers when explicitly requested
    #   https://stackoverflow.com/questions/9859627
    #   https://stackoverflow.com/questions/86105
    if get_header("X-Requested-With", request.headers) == "XMLHttpRequest":
        return None

    # select error type: https://tools.ietf.org/html/rfc6750#section-3.1
    if error_type not in ["invalid_request", "invalid_token", "insufficient_scope"]:
        error_type = "invalid_token"
    cookie_name = get_constant("MAGPIE_COOKIE_NAME", request)
    magpie_url = get_magpie_url(request)
    signin_url = "{}{}".format(magpie_url, SigninAPI.path)
    login_url = "{}/ui/login".format(magpie_url)
    hostname = urlparse(magpie_url).hostname
    title = "{} Login".format(__meta__.__title__)
    headers = {
        # Challenge Schema: https://tools.ietf.org/html/rfc2617#section-3.2.1  (section for schema of extra params)
        #   WWW-Authenticate: challenge-1 [realm="<>" title="<>" ...],
        #                     challenge-2 [...], ...
        # provide URL with both 'domain' and 'uri' which are two variants that can exist, depending on implementation
        "WWW-Authenticate": ("Cookie cookie-name=\"{c}\" error=\"{e}\" title=\"{t}\" "
                             "domain=\"{u}\" uri=\"{u}\" realm=\"{r}\" "
                             .format(c=cookie_name, e=error_type, u=signin_url, r=hostname, t=title)),
        # https://tools.ietf.org/html/rfc8053#section-4.3
        "Location-When-Unauthenticated": login_url,
    }
    return headers


def get_admin_cookies(container, verify=True, raise_message=None):
    # type: (AnySettingsContainer, bool, Optional[Str]) -> CookiesType
    from magpie.api.schemas import SigninAPI  # pylint: disable=C0415

    magpie_url = get_magpie_url(container)
    magpie_login_url = "{}{}".format(magpie_url, SigninAPI.path)
    cred = {"user_name": get_constant("MAGPIE_ADMIN_USER", container),
            "password": get_constant("MAGPIE_ADMIN_PASSWORD", container)}
    resp = requests.post(magpie_login_url, data=cred, headers={"Accept": CONTENT_TYPE_JSON}, verify=verify)
    if resp.status_code != HTTPOk.code:
        if raise_message:
            raise_log(raise_message, logger=LOGGER)
        raise resp.raise_for_status()
    token_name = get_constant("MAGPIE_COOKIE_NAME", container)

    # use specific domain to differentiate between `.{hostname}` and `{hostname}` variations if applicable
    request_cookies = resp.cookies
    magpie_cookies = list(filter(lambda cookie: cookie.name == token_name, request_cookies))
    magpie_domain = urlparse(magpie_url).hostname if len(magpie_cookies) > 1 else None
    session_cookies = RequestsCookieJar.get(request_cookies, token_name, domain=magpie_domain)

    return {token_name: session_cookies}


def get_settings(container, app=False):
    # type: (Optional[AnySettingsContainer], bool) -> SettingsType
    """
    Retrieve application settings from a supported container.

    :param container: supported container with an handle to application settings.
    :param app: allow retrieving from current thread registry if no container was defined.
    :return: found application settings dictionary.
    :raise TypeError: when no application settings could be found or unsupported container.
    """
    if isinstance(container, (Configurator, Request)):
        return container.registry.settings  # noqa
    if isinstance(container, Registry):
        return container.settings
    if isinstance(container, dict):
        return container
    if container is None and app:
        print_log("Using settings from local thread.", level=logging.DEBUG)
        registry = get_current_registry()
        return registry.settings
    raise TypeError("Could not retrieve settings from container object [{}]".format(type(container)))


def patch_magpie_url(container):
    # type: (AnySettingsContainer) -> SettingsType
    """
    Updates potentially missing configuration settings for normal application execution.
    """
    settings = get_settings(container)
    try:
        get_magpie_url(settings)
    except ConfigurationError:
        magpie_url_template = "{scheme}://{hostname}:{port}"
        port = get_constant("MAGPIE_PORT", settings, raise_not_set=False)
        scheme = get_constant("MAGPIE_SCHEME", settings, raise_missing=False, raise_not_set=False, default_value="http")
        if port:
            settings["magpie.port"] = port
        hostname = get_constant("HOSTNAME")
        if hostname:
            magpie_url = magpie_url_template.format(scheme=scheme, hostname=hostname, port=settings["magpie.port"])
            print_log("Updating 'magpie.url' value: {}".format(magpie_url), LOGGER, logging.WARNING)
            settings["magpie.url"] = magpie_url
    return settings


def get_magpie_url(container=None):
    # type: (Optional[AnySettingsContainer]) -> Str
    """
    Obtains the configured Magpie URL entrypoint based on the various combinations of supported configuration settings.

    .. seealso::
        Documentation section :ref:`config_app_settings` for available setting combinations.

    :param container: container that provides access to application settings.
    :return: resolved Magpie URL
    """
    try:
        settings = get_settings(container, app=True)
        magpie_url = get_constant("MAGPIE_URL", settings, raise_missing=False, raise_not_set=False, print_missing=False)
        if not magpie_url:
            hostname = (get_constant("MAGPIE_HOST", settings, raise_not_set=False, raise_missing=False,
                                     print_missing=True) or
                        get_constant("HOSTNAME", settings, raise_not_set=False, raise_missing=False,
                                     print_missing=True, default_value="localhost"))
            if not hostname:
                raise ConfigurationError("Missing, unset or empty value for MAGPIE_HOST or HOSTNAME setting.")
            magpie_port = get_constant("MAGPIE_PORT", settings, print_missing=True,
                                       raise_not_set=False, raise_missing=False, default_value=2001)
            magpie_scheme = get_constant("MAGPIE_SCHEME", settings, print_missing=True,
                                         raise_not_set=False, raise_missing=False, default_value="http")
            magpie_url = "{}://{}{}".format(magpie_scheme, hostname, ":{}".format(magpie_port) if magpie_port else "")

        # add "http" scheme to url if omitted from config since further 'requests' calls fail without it
        # mostly for testing when only "localhost" is specified
        # otherwise config should explicitly define it with 'MAGPIE_URL' env or 'magpie.url' config
        url_parsed = urlparse(magpie_url.strip("/"))
        if url_parsed.scheme in ["http", "https"]:
            return url_parsed.geturl()
        magpie_url = "http://{}".format(url_parsed.geturl())
        print_log("Missing scheme from settings URL, new value: '{}'".format(magpie_url), LOGGER, logging.WARNING)
        settings.setdefault("magpie.url", magpie_url)  # simplify the process for direct retrieval next time
        return magpie_url
    except AttributeError:
        # If magpie.url does not exist, calling strip fct over None will raise this issue
        raise ConfigurationError("MAGPIE_URL or magpie.url config cannot be found")


def get_phoenix_url(container=None):
    # type: (Optional[AnySettingsContainer]) -> Str
    """
    Obtains the configured Phoenix URL entrypoint based on the various combinations of supported configuration settings.

    .. seealso::
        Documentation section :ref:`config_phoenix` for available setting combinations.

    :param container: container that provides access to application settings.
    :return: resolved Phoenix URL
    """
    hostname = (get_constant("PHOENIX_HOST", container, raise_missing=False, raise_not_set=False) or
                get_constant("HOSTNAME", raise_missing=False, raise_not_set=False))
    if not hostname:
        raise ConfigurationError("Missing or unset PHOENIX_HOST or HOSTNAME value.")
    phoenix_port = get_constant("PHOENIX_PORT", raise_not_set=False)
    return "https://{0}{1}".format(hostname, ":{}".format(phoenix_port) if phoenix_port else "")


def get_twitcher_url(container=None, hostname=None):
    # type: (Optional[AnySettingsContainer], Optional[Str]) -> Str
    """
    Obtains the configured Twitcher URL entrypoint based on various combinations of supported configuration settings.

    .. seealso::
        Documentation section :ref:`config_twitcher` for available setting combinations.

    :param container: container that provides access to application settings.
    :param hostname: override literal hostname to generate the URL instead of resolving using settings.
    :return: resolved Twitcher URL
    """
    twitcher_proxy_url = get_constant("TWITCHER_PROTECTED_URL", container, raise_not_set=False)
    if not twitcher_proxy_url:
        twitcher_proxy = get_constant("TWITCHER_PROTECTED_PATH", container, raise_not_set=False)
        if not twitcher_proxy.endswith("/"):
            twitcher_proxy = twitcher_proxy + "/"
        if not twitcher_proxy.startswith("/"):
            twitcher_proxy = "/" + twitcher_proxy
        if not twitcher_proxy.startswith("/twitcher"):
            twitcher_proxy = "/twitcher" + twitcher_proxy
        hostname = (hostname or
                    get_constant("TWITCHER_HOST", container, raise_not_set=False, raise_missing=False) or
                    get_constant("HOSTNAME", container, raise_not_set=False, raise_missing=False))
        if not hostname:
            raise ConfigurationError("Missing or unset TWITCHER_PROTECTED_URL, TWITCHER_HOST or HOSTNAME value.")
        twitcher_proxy_url = "https://{0}{1}".format(hostname, twitcher_proxy)
    twitcher_proxy_url = twitcher_proxy_url.rstrip("/")
    return twitcher_proxy_url


def get_twitcher_protected_service_url(magpie_service_name, container=None, hostname=None):
    """
    Obtains the protected service URL behind Twitcher Proxy based on combination of supported configuration settings.

    .. seealso::
        Documentation section :ref:`config_twitcher` for available setting combinations.

    :param magpie_service_name: name of the service to employ in order to form the URL path behind the proxy.
    :param container: container that provides access to application settings.
    :param hostname: override literal hostname to generate the URL instead of resolving using settings.
    :return: resolved Twitcher Proxy protected service URL
    """
    twitcher_proxy_url = get_twitcher_url(container=container, hostname=hostname)
    return "{0}/{1}".format(twitcher_proxy_url, magpie_service_name)


def is_magpie_ui_path(request):
    # type: (Request) -> bool
    """
    Determines if the request path corresponds to any Magpie UI location.
    """
    # server URL could have more prefixes than only /magpie, so start by removing them using explicit URL setting
    # remove any additional hostname and known /magpie prefix to get only the final magpie-specific path
    magpie_url = get_magpie_url(request)
    magpie_url = request.url.replace(magpie_url, "")
    magpie_path = str(urlparse(magpie_url).path)
    magpie_path = magpie_path.split("/magpie/", 1)[-1]  # make sure we don't split a /magpie(.*) element by mistake
    magpie_path = "/" + magpie_path if not magpie_path.startswith("/") else magpie_path
    magpie_ui_home = asbool(get_constant("MAGPIE_UI_ENABLED", request)) and magpie_path in ("", "/")
    # ignore types defined under UI or static routes to allow rendering
    return magpie_ui_home or any(magpie_path.startswith(p) for p in ("/api", "/ui", "/static"))


def fully_qualified_name(obj):
    # type: (Union[Any, Type[Any]]) -> str
    """
    Obtains the ``'<module>.<name>'`` full path definition of the object to allow finding and importing it.
    """
    # pylint: disable=no-member
    if ismethod(obj):
        if six.PY2:
            cls = obj.im_class
            return ".".join([cls.__module__, cls.__name__, obj.__name__])
        return ".".join([obj.__module__, obj.__qualname__])
    cls = obj if isclass(obj) or inspect.isfunction(obj) else type(obj)
    return ".".join([obj.__module__, cls.__name__])


def log_request_format(request):
    # type: (Request) -> Str
    return "{!s} {!s} {!s}".format(request.method, request.host, request.path)


def log_request(event):
    # type: (NewRequest) -> None
    """
    Subscriber event that logs basic details about the incoming requests.
    """
    request = event.request  # type: Request
    LOGGER.info("Request: [%s]", log_request_format(request))
    if LOGGER.isEnabledFor(logging.DEBUG):
        def items_str(items):
            return "\n  ".join(["{!s}: {!s}".format(h, items[h]) for h in items]) if len(items) else "-"

        header_str = items_str(request.headers)
        params_str = items_str(request.params)
        body_str = str(request.body) or "-"
        LOGGER.debug("Request details:\n"
                     "URL: %s\n"
                     "Path: %s\n"
                     "Method: %s\n"
                     "Headers:\n"
                     "  %s\n"
                     "Parameters:\n"
                     "  %s\n"
                     "Body:\n"
                     "  %s",
                     request.url, request.path, request.method, header_str, params_str, body_str)


def log_exception_tween(handler, registry):  # noqa: F811
    """
    Tween factory that logs any exception before re-raising it.

    Application errors are marked as ``ERROR`` while non critical HTTP errors are marked as ``WARNING``.
    """
    def log_exc(request):
        try:
            return handler(request)
        except Exception as err:
            lvl = logging.ERROR
            exc = True
            if isinstance(err, HTTPClientError):
                lvl = logging.WARNING
                exc = False
            LOGGER.log(lvl, "Exception during request: [%s]", log_request_format(request), exc_info=exc)
            raise err
    return log_exc


def is_json_body(body, return_body=False):
    # type: (Any, bool) -> bool
    if not body:
        return None if return_body else False
    try:
        content = json.loads(body)
    except (ValueError, TypeError):
        return None if return_body else False
    return content if return_body else True


# note: must not define any enum value here to allow inheritance by subclasses
class ExtendedEnum(Enum):
    """
    Utility :class:`enum.Enum` methods.

    Create an extended enum with these utilities as follows::

        class CustomEnum(ExtendedEnum):
            ItemA = "A"
            ItemB = "B"
    """

    @classmethod
    def names(cls):
        # type: () -> List[Str]
        """
        Returns the member names assigned to corresponding enum elements.
        """
        return list(cls.__members__)

    @classmethod
    def values(cls):
        # type: () -> List[AnyKey]
        """
        Returns the literal values assigned to corresponding enum elements.
        """
        return [m.value for m in cls.__members__.values()]                      # pylint: disable=E1101

    @classmethod
    def get(cls, key_or_value, default=None):
        # type: (AnyKey, Optional[Any]) -> Optional[_TC]
        """
        Finds an enum entry by defined name or its value.

        Returns the entry directly if it is already a valid enum.
        """
        # Python 3.8 disallow direct check of 'str' in 'enum'
        members = [member for member in cls]
        if key_or_value in members:                                             # pylint: disable=E1133
            return key_or_value
        for m_key, m_val in cls.__members__.items():                            # pylint: disable=E1101
            if key_or_value == m_key or key_or_value == m_val.value:            # pylint: disable=R1714
                return m_val
        return default

    @classmethod
    def titles(cls):
        # type: () -> List[Str]
        """
        Returns the title representation of all enum elements.
        """
        return list(member.title for member in cls.__members__.values())

    @property
    def title(self):
        # type: () -> Str
        """
        Returns the title representation of the enum element.

        Title use the original enum element name with capitalization considering underscores for separate words.
        """
        return self.name.title().replace("_", "")


# note: must not define any enum value here to allow inheritance by subclasses
class FlexibleNameEnum(ExtendedEnum):
    """
    Enum that allows more permissive name cases for lookup.
    """

    @classmethod
    def _missing_(cls, value):
        return cls.__missing_flexible(value)

    @classmethod
    def __missing_flexible(cls, value):
        for name, item in cls.__members__.items():
            if value in [name, name.lower(), name.upper(), name.title()]:
                return item
        return super(FlexibleNameEnum, cls)._missing_(value)

    @classmethod
    def get(cls, key_or_value, default=None):
        try:
            result = super(FlexibleNameEnum, cls).get(key_or_value)
            if result is not None:
                return cls(result)  # noqa
            # use __missing_flexible instead of _missing_
            # otherwise, _missing_ of another enum sub-class (eg: IntFlag) get called and raises directly
            return cls.__missing_flexible(key_or_value)
        except ValueError:
            pass
        return default


def decompose_enum_flags(enum_flags):
    # type: (Enum) -> List[Enum]
    """
    Decompose a ``Flag``-enabled ``Enum`` into its individual parts.

    The operation is agnostic of the ``Enum`` implementation, whether from stdlib :mod:`enum` or :mod:`aenum`.
    """
    return [flag for flag in type(enum_flags).__members__.values() if flag in enum_flags]


# taken from https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
# works in Python 2 & 3
class SingletonMeta(type):
    """
    A metaclass that creates a Singleton base class when called.

    Create a class such that::

        @six.add_metaclass(SingletonMeta)
        class A(object):
            pass

        @six.add_metaclass(SingletonMeta)
        class B(object):
            pass

        a1 = A()
        a2 = A()
        b1 = B()
        b2 = B()
        a1 is a2    # True
        b1 is b2    # True
        a1 is b1    # False
    """
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(SingletonMeta, cls).__call__(*args, **kwargs)
        return cls._instances[cls]
