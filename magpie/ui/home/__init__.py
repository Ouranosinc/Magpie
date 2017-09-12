import logging
import requests
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Authenticated

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
        all_data.update({'logged_user': logged_user})
    return all_data


def includeme(config):
    logger.info('Adding home ...')
    config.add_route('home', '/')
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.scan()
