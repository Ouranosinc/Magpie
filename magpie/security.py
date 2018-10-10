from magpie.definitions.pyramid_definitions import *
from magpie.definitions.ziggurat_definitions import *
from magpie.api.login import esgfopenid, wso2
from magpie.constants import get_constant
from magpie import models
from authomatic import Authomatic, provider_id
from authomatic.providers import oauth2, openid
import os
import logging
logger = logging.getLogger(__name__)


def auth_config_from_settings(settings):
    magpie_secret = get_constant('MAGPIE_SECRET', settings=settings, settings_name='magpie.secret')
    authn_policy = AuthTktAuthenticationPolicy(
        magpie_secret,
        callback=groupfinder,
    )
    authz_policy = ACLAuthorizationPolicy()

    config = Configurator(
        settings=settings,
        root_factory=models.RootFactory,
        authentication_policy=authn_policy,
        authorization_policy=authz_policy
    )
    return config


def authomatic_setup(request):
    magpie_secret = get_constant('MAGPIE_SECRET', settings=request.registry.settings, settings_name='magpie.secret')
    return Authomatic(
        config=authomatic_config(request),
        secret=magpie_secret,
        report_errors=True,
        logging_level=logger.level
    )


def authomatic_config(request=None):

    DEFAULTS = {
        'popup': True,
    }

    OPENID = {
        'openid': {
            'class_': openid.OpenID,
            'display_name': 'OpenID',
        },
    }

    ESGF = {
        'dkrz': {
            'class_': esgfopenid.ESGFOpenID,
            'provider': 'dkrz',
            'hostname': 'esgf-data.dkrz.de',
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

    github_consumer_key = get_constant('GITHUB_CLIENT_ID', '#####')
    github_consumer_secret = get_constant('GITHUB_CLIENT_SECRET', '#####')
    wso2_hostname = get_constant('WSO2_HOSTNAME')
    wso2_consumer_key = get_constant('WSO2_CLIENT_ID', '#####')
    wso2_consumer_secret = get_constant('WSO2_CLIENT_SECRET', '#####')
    OAUTH2 = {
        'github': {
            'class_': oauth2.GitHub,
            'display_name': 'GitHub',
            'consumer_key': github_consumer_key,
            'consumer_secret': github_consumer_secret,
            'redirect_uri': request.application_url if request else None,
            'access_headers': {'User-Agent': 'Magpie'},
            'id': provider_id(),
            'scope': oauth2.GitHub.user_info_scope,
            '_apis': {
                'Get your events': ('GET', 'https://api.github.com/users/{user.username}/events'),
                'Get your watched repos': ('GET', 'https://api.github.com/user/subscriptions'),
            },
        },
        'wso2': {
            'class_': wso2.WSO2,
            'display_name': 'WSO2',
            'hostname': wso2_hostname,
            'consumer_key': wso2_consumer_key,
            'consumer_secret': wso2_consumer_secret,
            'redirect_uri': request.application_url if request else None,
            #'access_headers': {},
            'id': provider_id(),
            'scope': wso2.WSO2.user_info_scope,
        }
    }

    # Concatenate the configs.
    config = {}
    config.update(OAUTH2)
    config.update(OPENID)
    config.update(ESGF)
    config['__defaults__'] = DEFAULTS
    return config


def get_provider_names():
    provider_names = {}
    config = authomatic_config()
    for provider in config.keys():
        if provider != '__defaults__':
            provider_names[provider] = config[provider].get('display_name', provider)
    return provider_names
