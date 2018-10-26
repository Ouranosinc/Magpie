from magpie.constants import get_constant
from magpie.definitions.pyramid_definitions import HTTPOk, ConfigurationError, Registry
from six.moves.urllib.parse import urlparse
from typing import Dict
import requests
import logging
LOGGER = logging.getLogger("TWITCHER")


def get_admin_cookies(magpie_url, verify=True):
    # type: (str, bool) -> Dict[str,str]
    magpie_login_url = '{}/signin'.format(magpie_url)
    cred = {'user_name': get_constant('MAGPIE_ADMIN_USER'), 'password': get_constant('MAGPIE_ADMIN_PASSWORD')}
    resp = requests.post(magpie_login_url, data=cred, headers={'Accept': 'application/json'}, verify=verify)
    if resp.status_code != HTTPOk.code:
        raise resp.raise_for_status()
    return dict(auth_tkt=resp.cookies.get('auth_tkt'))


def get_magpie_url(registry):
    # type: (Registry) -> str
    try:
        # add 'http' scheme to url if omitted from config since further 'requests' calls fail without it
        # mostly for testing when only 'localhost' is specified
        # otherwise twitcher config should explicitly define it in MAGPIE_URL
        url_parsed = urlparse(registry.settings.get('magpie.url').strip('/'))
        if url_parsed.scheme in ['http', 'https']:
            return url_parsed.geturl()
        else:
            magpie_url = 'http://{}'.format(url_parsed.geturl())
            LOGGER.warn("Missing scheme from registry url, new value: '{}'".format(magpie_url))
            return magpie_url
    except AttributeError:
        # If magpie.url does not exist, calling strip fct over None will raise this issue
        raise ConfigurationError('magpie.url config cannot be found')
