from magpie.definitions.pyramid_definitions import IAuthenticationPolicy, Authenticated
from magpie.common import get_logger
LOGGER = get_logger(__name__)


def add_template_data(request, data=None):
    all_data = data or {}
    magpie_logged_user = None
    LOGGER.warning('add magpie logged user')  # TODO: remove
    try:
        authn_policy = request.registry.queryUtility(IAuthenticationPolicy)
        principals = authn_policy.effective_principals(request)

        if Authenticated in principals:
            LOGGER.info('User {0} is authenticated'.format(request.user.user_name))
            magpie_logged_user = request.user.user_name
    except AttributeError:
        pass
    LOGGER.warning('set magpie logged user: {}'.format(magpie_logged_user))  # TODO: remove
    if magpie_logged_user:
        all_data.update({u'MAGPIE_LOGGED_USER': magpie_logged_user})
    return all_data


def includeme(config):
    LOGGER.info('Adding home ...')
    config.add_route('home', '/')
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.scan()
