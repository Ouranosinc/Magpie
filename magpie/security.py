from authomatic import Authomatic, provider_id
from authomatic.providers import oauth2, openid
from esgf import esgfopenid
import os
import logging
logger = logging.getLogger(__name__)

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