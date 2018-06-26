import logging
import requests
from definitions.pyramid_definitions import *

logger = logging.getLogger(__name__)


def add_template_data(request, data=None):
    all_data = data or {}
    logged_user = None

    try:
        authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
        principals = authn_policy.effective_principals(request)

        if Authenticated in principals:
            logger.info('User {0} is authenticated'.format(request.user.user_name))
            logged_user = request.user.user_name
    except AttributeError:
        pass

    if logged_user:
        all_data.update({u'logged_user': logged_user})
    return all_data


def includeme(config):
    logger.info('Adding home ...')
    config.add_route('home', '/')
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.scan()
