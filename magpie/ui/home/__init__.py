from magpie.definitions.pyramid_definitions import IAuthenticationPolicy, Authenticated
import logging
logger = logging.getLogger(__name__)


def add_template_data(request, data=None):
    all_data = data or {}
    MAGPIE_LOGGED_USER = None

    try:
        authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
        principals = authn_policy.effective_principals(request)

        if Authenticated in principals:
            logger.info('User {0} is authenticated'.format(request.user.user_name))
            MAGPIE_LOGGED_USER = request.user.user_name
    except AttributeError:
        pass

    if MAGPIE_LOGGED_USER:
        all_data.update({u'MAGPIE_LOGGED_USER': MAGPIE_LOGGED_USER})
    return all_data


def includeme(config):
    logger.info('Adding home ...')
    config.add_route('home', '/')
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.scan()
