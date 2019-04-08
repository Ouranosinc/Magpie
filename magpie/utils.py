from magpie.common import raise_log, get_logger, JSON_TYPE
from magpie.constants import get_constant
from magpie.definitions.pyramid_definitions import (
    HTTPOk, HTTPClientError, ConfigurationError, Configurator, Registry, Request
)
from six.moves.urllib.parse import urlparse
from typing import TYPE_CHECKING
from requests.cookies import RequestsCookieJar
import logging
import requests
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Str, CookiesType, SettingsType, SettingsContainer, Optional  # noqa: F401
LOGGER = get_logger(__name__)


def get_admin_cookies(magpie_url, verify=True, raise_message=None):
    # type: (Str, Optional[bool], Optional[Str]) -> CookiesType
    magpie_login_url = '{}/signin'.format(magpie_url)
    cred = {'user_name': get_constant('MAGPIE_ADMIN_USER'), 'password': get_constant('MAGPIE_ADMIN_PASSWORD')}
    resp = requests.post(magpie_login_url, data=cred, headers={'Accept': JSON_TYPE}, verify=verify)
    if resp.status_code != HTTPOk.code:
        if raise_message:
            raise_log(raise_message, logger=LOGGER)
        raise resp.raise_for_status()
    token_name = get_constant('MAGPIE_COOKIE_NAME')

    # use specific domain to differentiate between `.{hostname}` and `{hostname}` variations if applicable
    # noinspection PyProtectedMember
    request_cookies = resp.cookies
    magpie_cookies = list(filter(lambda cookie: cookie.name == token_name, request_cookies))
    magpie_domain = urlparse(magpie_url).hostname if len(magpie_cookies) > 1 else None
    session_cookies = RequestsCookieJar.get(request_cookies, token_name, domain=magpie_domain)

    return {token_name: session_cookies}


def get_settings(container):
    # type: (SettingsContainer) -> SettingsType
    if isinstance(container, (Configurator, Request)):
        return container.registry.settings
    if isinstance(container, Registry):
        return container.settings
    if isinstance(container, dict):
        return container
    raise TypeError("Could not retrieve settings from container object [{}]".format(type(container)))


def patch_magpie_url(container):
    # type: (SettingsContainer) -> SettingsType
    """Updates potentially missing configuration settings for normal application execution."""
    settings = get_settings(container)
    try:
        get_magpie_url(settings)
    except ConfigurationError:
        magpie_url_template = 'http://{hostname}:{port}'
        port = get_constant('MAGPIE_PORT', settings, settings_name='magpie.port')
        if port:
            settings['magpie.port'] = port
        hostname = get_constant('HOSTNAME')
        if hostname:
            settings['magpie.url'] = magpie_url_template.format(hostname=hostname, port=settings['magpie.port'])
    return settings


def get_magpie_url(container=None):
    # type: (Optional[SettingsContainer]) -> Str
    if container is None:
        LOGGER.warning("Registry not specified, trying to find Magpie URL from environment")
        url = get_constant('MAGPIE_URL', raise_missing=False, raise_not_set=False, print_missing=False)
        if url:
            return url
        hostname = get_constant('HOSTNAME', raise_not_set=False, raise_missing=False) or \
                   get_constant('MAGPIE_HOST', raise_not_set=False, raise_missing=False)    # noqa
        if not hostname:
            raise ConfigurationError('Missing or unset MAGPIE_HOST or HOSTNAME value.')
        magpie_port = get_constant('MAGPIE_PORT', raise_not_set=False)
        return 'http://{0}{1}'.format(hostname, ':{}'.format(magpie_port) if magpie_port else '')
    try:
        # add 'http' scheme to url if omitted from config since further 'requests' calls fail without it
        # mostly for testing when only 'localhost' is specified
        # otherwise twitcher config should explicitly define it in MAGPIE_URL
        settings = get_settings(container)
        url_parsed = urlparse(get_constant('MAGPIE_URL', settings, 'magpie.url').strip('/'))
        if url_parsed.scheme in ['http', 'https']:
            return url_parsed.geturl()
        else:
            magpie_url = 'http://{}'.format(url_parsed.geturl())
            LOGGER.warning("Missing scheme from settings URL, new value: '{}'".format(magpie_url))
            return magpie_url
    except AttributeError:
        # If magpie.url does not exist, calling strip fct over None will raise this issue
        raise ConfigurationError('MAGPIE_URL or magpie.url config cannot be found')


def get_phoenix_url():
    hostname = get_constant('HOSTNAME')
    phoenix_port = get_constant('PHOENIX_PORT', raise_not_set=False)
    return 'https://{0}{1}'.format(hostname, ':{}'.format(phoenix_port) if phoenix_port else '')


def get_twitcher_protected_service_url(magpie_service_name, hostname=None):
    twitcher_proxy_url = get_constant('TWITCHER_PROTECTED_URL', raise_not_set=False)
    if not twitcher_proxy_url:
        twitcher_proxy = get_constant('TWITCHER_PROTECTED_PATH', raise_not_set=False)
        if not twitcher_proxy.endswith('/'):
            twitcher_proxy = twitcher_proxy + '/'
        if not twitcher_proxy.startswith('/'):
            twitcher_proxy = '/' + twitcher_proxy
        if not twitcher_proxy.startswith('/twitcher'):
            twitcher_proxy = '/twitcher' + twitcher_proxy
        hostname = hostname or get_constant('HOSTNAME')
        twitcher_proxy_url = "https://{0}{1}".format(hostname, twitcher_proxy)
    twitcher_proxy_url = twitcher_proxy_url.rstrip('/')
    return "{0}/{1}".format(twitcher_proxy_url, magpie_service_name)


def log_request_format(request):
    # type: (Request) -> Str
    return "{!s:8} {!s} {!s}".format(request.method, request.host, request.path)


def log_request(event):
    """Subscriber event that logs basic details about the incoming requests."""
    LOGGER.info("Request: [{}]".format(log_request_format(event.request)))


# noinspection PyUnusedLocal
def log_exception(handler, registry):
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


class ClassPropertyDescriptor(object):

    def __init__(self, fget, fset=None):
        self.fget = fget
        self.fset = fset

    def __get__(self, obj, klass=None):
        if klass is None:
            klass = type(obj)
        return self.fget.__get__(obj, klass)()

    def __set__(self, obj, value):
        if not self.fset:
            raise AttributeError("can't set attribute")
        type_ = type(obj)
        return self.fset.__get__(obj, type_)(value)

    def setter(self, func):
        if not isinstance(func, (classmethod, staticmethod)):
            func = classmethod(func)
        self.fset = func
        return self


def classproperty(func):
    if not isinstance(func, (classmethod, staticmethod)):
        func = classmethod(func)

    return ClassPropertyDescriptor(func)
