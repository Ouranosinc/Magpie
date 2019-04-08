from magpie.api.login import esgfopenid, wso2
from magpie.common import get_logger
from magpie.constants import get_constant
from magpie.definitions.pyramid_definitions import (
    AuthTktAuthenticationPolicy, ACLAuthorizationPolicy, Configurator, asbool
)
from magpie.definitions.ziggurat_definitions import groupfinder
from authomatic import Authomatic, provider_id
from authomatic.providers import oauth2, openid
from typing import TYPE_CHECKING
import logging
if TYPE_CHECKING:
    from magpie.definitions.typedefs import JSON  # noqa: F401
AUTHOMATIC_LOGGER = get_logger('magpie.authomatic', level=logging.DEBUG)


def auth_config_from_settings(settings):
    magpie_secret = get_constant('MAGPIE_SECRET', settings, settings_name='magpie.secret')
    magpie_cookie_expire = get_constant('MAGPIE_COOKIE_EXPIRE', settings,
                                        settings_name='magpie.cookie_expire', default_value=None,
                                        raise_missing=False, raise_not_set=False, print_missing=True)
    magpie_cookie_name = get_constant('MAGPIE_COOKIE_NAME', settings,
                                      settings_name='magpie.cookie_name', default_value='auth_tkt',
                                      raise_missing=False, raise_not_set=False, print_missing=True)
    authn_policy = AuthTktAuthenticationPolicy(
        magpie_secret,
        cookie_name=magpie_cookie_name,
        callback=groupfinder,
        # Protect against JavaScript CSRF attacks attempting cookies retrieval
        http_only=True,
        # Automatically refresh the cookie unless inactivity reached 'timeout'
        timeout=magpie_cookie_expire,
        reissue_time=int(magpie_cookie_expire) / 10 if magpie_cookie_expire else None,
    )
    authz_policy = ACLAuthorizationPolicy()

    from magpie import models
    config = Configurator(
        settings=settings,
        root_factory=models.RootFactory,
        authentication_policy=authn_policy,
        authorization_policy=authz_policy
    )
    return config


def authomatic_setup(request):
    magpie_secret = get_constant('MAGPIE_SECRET', request, settings_name='magpie.secret')
    return Authomatic(
        config=authomatic_config(request),
        secret=magpie_secret,
        logger=AUTHOMATIC_LOGGER,
        report_errors=True,
        logging_level=AUTHOMATIC_LOGGER.level
    )


# noinspection PyPep8Naming
def authomatic_config(request=None):

    defaults_config = {
        'popup': True,
    }

    openid_config = {
        'openid': {
            'class_': openid.OpenID,
            'display_name': 'OpenID',
        },
    }

    esgf_config = {
        'dkrz': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'esgf-data.dkrz.de',
            'provider_url': 'https://{hostname}/esgf-idp/openid/{username}',
            'display_name': 'DKRZ',
        },
        'ipsl': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'providers-node.ipsl.fr',
            'display_name': 'IPSL',
        },
        'badc': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'ceda.ac.uk',
            'provider_url': 'https://{hostname}/openid/{username}',
            'display_name': 'BADC',
        },
        'pcmdi': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'providers-node.llnl.gov',
            'display_name': 'PCMDI',
        },
        'smhi': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'esg-dn1.nsc.liu.se',
            'display_name': 'SMHI',
        },
    }

    _get_const_info = dict(raise_missing=False, raise_not_set=False, print_missing=True)
    oauth2_config = {
        'github': {
            'class_': oauth2.GitHub,
            'display_name': 'GitHub',
            'consumer_key': get_constant('GITHUB_CLIENT_ID', **_get_const_info),
            'consumer_secret': get_constant('GITHUB_CLIENT_SECRET', **_get_const_info),
            'redirect_uri': request.application_url if request else None,
            # 'redirect_uri': '{}/providers/github/signin'.format(request.application_url) if request else None,
            'access_headers': {'User-Agent': 'Magpie'},
            'id': provider_id(),
            '_apis': {
                'Get your events': ('GET', 'https://api.github.com/users/{user.username}/events'),
                'Get your watched repos': ('GET', 'https://api.github.com/user/subscriptions'),
            },
        },
        'wso2': {
            'class_': wso2.WSO2,
            'display_name': 'WSO2',
            'hostname': get_constant('WSO2_HOSTNAME', **_get_const_info),
            'consumer_key': get_constant('WSO2_CLIENT_ID', **_get_const_info),
            'consumer_secret': get_constant('WSO2_CLIENT_SECRET', **_get_const_info),
            'certificate_file': get_constant('WSO2_CERTIFICATE_FILE', **_get_const_info) or None,  # replace if == ''
            'ssl_verify': asbool(get_constant('WSO2_SSL_VERIFY', default_value=True, **_get_const_info)),
            'redirect_uri': '{}/providers/wso2/signin'.format(request.application_url) if request else None,
            'id': provider_id(),
        }
    }

    # Concatenate the configs.
    config = {}  # type: JSON
    config.update(oauth2_config)
    config.update(openid_config)
    config.update(esgf_config)
    config['__defaults__'] = defaults_config
    return config


def get_provider_names():
    provider_names = {}
    config = authomatic_config()
    for provider in config.keys():
        if provider != '__defaults__':
            provider_names[provider.lower()] = config[provider].get('display_name', provider)
    return provider_names
