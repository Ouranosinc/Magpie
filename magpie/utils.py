#!/usr/bin/env python
# -*- coding: utf-8 -*-
from magpie.constants import get_constant
from magpie.definitions.pyramid_definitions import (
    HTTPOk, HTTPClientError, HTTPException, ConfigurationError, Configurator, Registry, Request, Response, truthy
)
from six.moves.urllib.parse import urlparse
# noinspection PyProtectedMember
from enum import EnumMeta
from requests.cookies import RequestsCookieJar
from requests.structures import CaseInsensitiveDict
from webob.headers import ResponseHeaders, EnvironHeaders
from distutils.dir_util import mkpath
from six.moves import configparser
from typing import TYPE_CHECKING
import requests
import logging
import types
import six
import sys
import os
if TYPE_CHECKING:
    from magpie.definitions.typedefs import (  # noqa: F401
        Any, AnyKey, Str, List, Optional, Type, Union,
        AnyResponseType, AnyHeadersType, LoggerType, CookiesType, SettingsType, AnySettingsContainer,
    )
    from enum import Enum  # noqa: F401

CONTENT_TYPE_ANY = "*/*"
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_HTML = "text/html"
CONTENT_TYPE_PLAIN = "text/plain"
SUPPORTED_CONTENT_TYPES = [CONTENT_TYPE_JSON, CONTENT_TYPE_HTML, CONTENT_TYPE_PLAIN]


def get_logger(name, level=None):
    """
    Immediately sets the logger level to avoid duplicate log outputs
    from the `root logger` and `this logger` when `level` is `NOTSET`.
    """
    from magpie.constants import MAGPIE_LOG_LEVEL
    logger = logging.getLogger(name)
    logger.setLevel(level or MAGPIE_LOG_LEVEL)
    return logger


LOGGER = get_logger(__name__)


def print_log(msg, logger=None, level=logging.INFO):
    if not logger:
        logger = get_logger(__name__)
    all_handlers = logging.root.handlers + logger.handlers
    if not any(isinstance(h, logging.StreamHandler) for h in all_handlers):
        logger.addHandler(logging.StreamHandler(sys.stdout))
    if logger.disabled:
        logger.disabled = False
    logger.log(level, msg)


def raise_log(msg, exception=Exception, logger=None, level=logging.ERROR):
    # type: (Str, Optional[Type[Exception]], Optional[LoggerType], Optional[int]) -> None
    if not logger:
        logger = get_logger(__name__)
    logger.log(level, msg)
    if not hasattr(exception, "message"):
        exception = Exception
    raise exception(msg)


def bool2str(value):
    # type: (Any) -> Str
    return "true" if str(value).lower() in truthy else "false"


def islambda(func):
    return isinstance(func, types.LambdaType) and func.__name__ == (lambda: None).__name__


def isclass(obj):
    """
    Evaluate an object for class type (ie: class definition, not an instance nor any other type).

    :param obj: object to evaluate for class type
    :return: (bool) indicating if `object` is a class
    """
    return isinstance(obj, (type, six.class_types))


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
    parser.read([config_ini_path])
    settings = dict(parser.items(ini_main_section_name))
    return settings


def get_json(response):
    """
    Retrieves the 'JSON' body of a response using the property/callable
    according to the response's implementation.
    """
    if isinstance(response.json, dict):
        return response.json
    return response.json()


def get_header(header_name, header_container, default=None, split=None):
    # type: (Str, AnyHeadersType, Optional[Str], Optional[Union[Str, List[Str]]]) -> Optional[Str]
    """
    Retrieves ``header_name`` by fuzzy match (independently of upper/lower-case and underscore/dash)
    from various framework implementations of ``Headers``.

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
                for s in split:
                    v = v.replace(s, split[0])
                split = split[0]
            return (v.split(split)[0] if split else v).strip()
    return default


def convert_response(response):
    # type: (AnyResponseType) -> Response
    """
    Converts a ``response`` implementation (e.g.: ``requests.Response``)
    to an equivalent ``pyramid.response.Response`` version.
    """
    if isinstance(response, Response):
        return response
    json_body = get_json(response)
    pyramid_response = Response(body=json_body, headers=response.headers)
    if hasattr(response, "cookies"):
        for cookie in response.cookies:
            pyramid_response.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
    if isinstance(response, HTTPException):
        # noinspection PyProtectedMember
        for header_name, header_value in response.headers._items:
            if header_name.lower() == "set-cookie":
                pyramid_response.set_cookie(name=header_name, value=header_value, overwrite=True)
    return pyramid_response


def get_admin_cookies(magpie_url, verify=True, raise_message=None):
    # type: (Str, bool, Optional[Str]) -> CookiesType
    magpie_login_url = "{}/signin".format(magpie_url)
    cred = {"user_name": get_constant("MAGPIE_ADMIN_USER"), "password": get_constant("MAGPIE_ADMIN_PASSWORD")}
    resp = requests.post(magpie_login_url, data=cred, headers={"Accept": CONTENT_TYPE_JSON}, verify=verify)
    if resp.status_code != HTTPOk.code:
        if raise_message:
            raise_log(raise_message, logger=LOGGER)
        raise resp.raise_for_status()
    token_name = get_constant("MAGPIE_COOKIE_NAME")

    # use specific domain to differentiate between `.{hostname}` and `{hostname}` variations if applicable
    # noinspection PyProtectedMember
    request_cookies = resp.cookies
    magpie_cookies = list(filter(lambda cookie: cookie.name == token_name, request_cookies))
    magpie_domain = urlparse(magpie_url).hostname if len(magpie_cookies) > 1 else None
    session_cookies = RequestsCookieJar.get(request_cookies, token_name, domain=magpie_domain)

    return {token_name: session_cookies}


def get_settings(container):
    # type: (AnySettingsContainer) -> SettingsType
    if isinstance(container, (Configurator, Request)):
        return container.registry.settings
    if isinstance(container, Registry):
        return container.settings
    if isinstance(container, dict):
        return container
    raise TypeError("Could not retrieve settings from container object [{}]".format(type(container)))


def patch_magpie_url(container):
    # type: (AnySettingsContainer) -> SettingsType
    """Updates potentially missing configuration settings for normal application execution."""
    settings = get_settings(container)
    try:
        get_magpie_url(settings)
    except ConfigurationError:
        magpie_url_template = "http://{hostname}:{port}"
        port = get_constant("MAGPIE_PORT", settings, settings_name="magpie.port")
        if port:
            settings["magpie.port"] = port
        hostname = get_constant("HOSTNAME")
        if hostname:
            settings["magpie.url"] = magpie_url_template.format(hostname=hostname, port=settings["magpie.port"])
    return settings


def get_magpie_url(container=None):
    # type: (Optional[AnySettingsContainer]) -> Str
    if container is None:
        LOGGER.warning("Registry not specified, trying to find Magpie URL from environment")
        url = get_constant("MAGPIE_URL", raise_missing=False, raise_not_set=False, print_missing=False)
        if url:
            return url
        hostname = get_constant("HOSTNAME", raise_not_set=False, raise_missing=False) or \
                   get_constant("MAGPIE_HOST", raise_not_set=False, raise_missing=False)    # noqa
        if not hostname:
            raise ConfigurationError("Missing or unset MAGPIE_HOST or HOSTNAME value.")
        magpie_port = get_constant("MAGPIE_PORT", raise_not_set=False)
        return "http://{0}{1}".format(hostname, ":{}".format(magpie_port) if magpie_port else "")
    try:
        # add "http" scheme to url if omitted from config since further 'requests' calls fail without it
        # mostly for testing when only "localhost" is specified
        # otherwise twitcher config should explicitly define it in MAGPIE_URL
        settings = get_settings(container)
        url_parsed = urlparse(get_constant("MAGPIE_URL", settings, "magpie.url").strip("/"))
        if url_parsed.scheme in ["http", "https"]:
            return url_parsed.geturl()
        else:
            magpie_url = "http://{}".format(url_parsed.geturl())
            LOGGER.warning("Missing scheme from settings URL, new value: '{}'".format(magpie_url))
            return magpie_url
    except AttributeError:
        # If magpie.url does not exist, calling strip fct over None will raise this issue
        raise ConfigurationError("MAGPIE_URL or magpie.url config cannot be found")


def get_phoenix_url():
    hostname = get_constant("HOSTNAME")
    phoenix_port = get_constant("PHOENIX_PORT", raise_not_set=False)
    return "https://{0}{1}".format(hostname, ":{}".format(phoenix_port) if phoenix_port else "")


def get_twitcher_protected_service_url(magpie_service_name, hostname=None):
    twitcher_proxy_url = get_constant("TWITCHER_PROTECTED_URL", raise_not_set=False)
    if not twitcher_proxy_url:
        twitcher_proxy = get_constant("TWITCHER_PROTECTED_PATH", raise_not_set=False)
        if not twitcher_proxy.endswith("/"):
            twitcher_proxy = twitcher_proxy + "/"
        if not twitcher_proxy.startswith("/"):
            twitcher_proxy = "/" + twitcher_proxy
        if not twitcher_proxy.startswith("/twitcher"):
            twitcher_proxy = "/twitcher" + twitcher_proxy
        hostname = hostname or get_constant("HOSTNAME")
        twitcher_proxy_url = "https://{0}{1}".format(hostname, twitcher_proxy)
    twitcher_proxy_url = twitcher_proxy_url.rstrip("/")
    return "{0}/{1}".format(twitcher_proxy_url, magpie_service_name)


def log_request_format(request):
    # type: (Request) -> Str
    return "{!s} {!s} {!s}".format(request.method, request.host, request.path)


def log_request(event):
    """Subscriber event that logs basic details about the incoming requests."""
    LOGGER.info("Request: [{}]".format(log_request_format(event.request)))


# noinspection PyUnusedLocal
def log_exception_tween(handler, registry):
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
            LOGGER.log(lvl, "Exception during request: [{}]".format(log_request_format(request)), exc_info=exc)
            raise err
    return log_exc


class ExtendedEnumMeta(EnumMeta):
    def values(cls):
        # type: (Type[Enum]) -> List[AnyKey]
        """Returns the literal values assigned to each enum element."""
        return [m.value for m in cls.__members__.values()]

    def get(cls, key_or_value, default=None):
        # type: (Type[Enum], AnyKey, Optional[Any]) -> Optional[Type[Enum]]
        """Finds a enum entry by defined name or its value."""
        for m_key, m_val in cls.__members__.items():
            if key_or_value == m_key or key_or_value == m_val.value:
                return m_val
        return default
