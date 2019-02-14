from magpie.common import raise_log, get_logger
from magpie.constants import get_constant
from magpie.definitions.pyramid_definitions import HTTPOk, ConfigurationError, Registry
from six.moves.urllib.parse import urlparse
from typing import AnyStr, Dict, Optional
import requests
LOGGER = get_logger(__name__)


def get_admin_cookies(magpie_url, verify=True, raise_message=None):
    # type: (str, Optional[bool], Optional[AnyStr]) -> Dict[str,str]
    magpie_login_url = '{}/signin'.format(magpie_url)
    cred = {'user_name': get_constant('MAGPIE_ADMIN_USER'), 'password': get_constant('MAGPIE_ADMIN_PASSWORD')}
    resp = requests.post(magpie_login_url, data=cred, headers={'Accept': 'application/json'}, verify=verify)
    if resp.status_code != HTTPOk.code:
        if raise_message:
            raise_log(raise_message, logger=LOGGER)
        raise resp.raise_for_status()
    token_name = get_constant('MAGPIE_COOKIE_NAME')
    return {token_name: resp.cookies.get(token_name)}


def get_magpie_url(registry=None):
    # type: (Optional[Registry]) -> str
    if registry is None:
        LOGGER.warning("Registry not specified, trying to find Magpie URL from environment")
        hostname = get_constant('HOSTNAME')
        magpie_port = get_constant('MAGPIE_PORT', raise_not_set=False)
        return 'http://{0}{1}'.format(hostname, ':{}'.format(magpie_port) if magpie_port else '')
    try:
        # add 'http' scheme to url if omitted from config since further 'requests' calls fail without it
        # mostly for testing when only 'localhost' is specified
        # otherwise twitcher config should explicitly define it in MAGPIE_URL
        url_parsed = urlparse(registry.settings.get('magpie.url').strip('/'))
        if url_parsed.scheme in ['http', 'https']:
            return url_parsed.geturl()
        else:
            magpie_url = 'http://{}'.format(url_parsed.geturl())
            LOGGER.warning("Missing scheme from registry url, new value: '{}'".format(magpie_url))
            return magpie_url
    except AttributeError:
        # If magpie.url does not exist, calling strip fct over None will raise this issue
        raise ConfigurationError('magpie.url config cannot be found')


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
