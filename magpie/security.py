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
        config=authomatic_config(),
        secret=magpie_secret,
        report_errors=True,
        logging_level=logger.level
    )


def authomatic_config():

    DEFAULTS = {
        'popup': True,
    }

    OPENID = {
        'OpenID': {
            'class_': openid.OpenID,
        },
    }

    ESGF = {
        'DKRZ': {
            'class_': esgfopenid.ESGFOpenID,
            'provider': 'dkrz',
            'hostname': 'esgf-data.dkrz.de',
        },
        'IPSL': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'providers-node.ipsl.fr',
        },
        'BADC': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'ceda.ac.uk',
            'provider_url': 'https://{hostname}/openid/{username}'
        },
        'PCMDI': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'providers-node.llnl.gov',
        },
        'SMHI': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'esg-dn1.nsc.liu.se',
        },
    }

    github_consumer_key = os.getenv('GITHUB_CLIENT_ID', '#####')
    github_consumer_secret = os.getenv('GITHUB_CLIENT_SECRET', '#####')
    wso2_hostname = os.getenv('WSO2_HOSTNAME')
    wso2_consumer_key = os.getenv('WSO2_CLIENT_ID', '#####')
    wso2_consumer_secret = os.getenv('WSO2_CLIENT_SECRET', '#####')
    OAUTH2 = {
        'GitHub': {
            'class_': oauth2.GitHub,
            'consumer_key': github_consumer_key,
            'consumer_secret': github_consumer_secret,
            'access_headers': {'User-Agent': 'Magpie'},
            'id': provider_id(),
            'scope': oauth2.GitHub.user_info_scope,
            '_apis': {
                'Get your events': ('GET', 'https://api.github.com/users/{user.username}/events'),
                'Get your watched repos': ('GET', 'https://api.github.com/user/subscriptions'),
            },
        },
        'WSO2': {
            'class_': wso2.WSO2,
            'hostname': wso2_hostname,
            'consumer_key': wso2_consumer_key,
            'consumer_secret': wso2_consumer_secret,
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
