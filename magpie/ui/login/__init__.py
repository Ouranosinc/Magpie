from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.settings import asbool
from pyramid.view import view_config

from magpie.constants import get_constant
from magpie.ui.login.views import LoginViews
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding UI login...")
    config.add_route("login", "/ui/login")
    config.add_route("logout", "/ui/logout")
    register_user_enabled = asbool(get_constant("MAGPIE_USER_REGISTRATION_ENABLED", settings_container=config,
                                                default_value=False, print_missing=True,
                                                raise_missing=False, raise_not_set=False))
    if register_user_enabled:
        LOGGER.info("Adding UI user registration.")
        config.add_route("register_user", "/ui/register")
        config.add_view(LoginViews, attr="register_user", route_name="register_user",
                        renderer="magpie.ui.management:templates/add_user.mako", permission=NO_PERMISSION_REQUIRED)

    config.scan()
