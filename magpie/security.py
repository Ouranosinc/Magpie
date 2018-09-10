from magpie.definitions.pyramid_definitions import *
from magpie.definitions.ziggurat_definitions import *
from magpie.api.esgf import esgfopenid
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


def authomatic(request):
    return Authomatic(
        config=authomatic_config(request),
        secret='randomsecretstring',
        report_errors=True,
        logging_level=logger.level)


def authomatic_config(request):

    DEFAULTS = {
        'popup': True,
    }

    OPENID = {
        'openid': {
            'class_': openid.OpenID,
        },
    }

    ESGF = {
        'dkrz': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'esgf-data.dkrz.de',
        },
        'ipsl': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'esgf-node.ipsl.fr',
        },
        'badc': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'ceda.ac.uk',
            'provider_url': 'https://{hostname}/openid/{username}'
        },
        'pcmdi': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'esgf-node.llnl.gov',
        },
        'smhi': {
            'class_': esgfopenid.ESGFOpenID,
            'hostname': 'esg-dn1.nsc.liu.se',
        },
    }

    github_consumer_key = os.getenv('GITHUB_CLIENT_ID', '#####')
    github_consumer_secret = os.getenv('GITHUB_CLIENT_SECRET', '#####')
    OAUTH2 = {
        'github': {
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
    }

    # Concatenate the configs.
    config = {}
    config.update(OAUTH2)
    config.update(OPENID)
    config.update(ESGF)
    config['__defaults__'] = DEFAULTS
    return config
