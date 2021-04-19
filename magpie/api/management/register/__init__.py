from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.settings import asbool

from magpie.api import schemas as s
from magpie.api.management.register import register_views as rv
from magpie.utils import get_constant, get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding API register...")
    config.add_route(**s.service_api_route_info(s.RegisterGroupsAPI))
    config.add_route(**s.service_api_route_info(s.RegisterGroupAPI))
    config.add_route(**s.service_api_route_info(s.TemporaryUrlAPI))

    enable_register_user = get_constant("MAGPIE_USER_REGISTRATION", settings_container=config, default_value=False,
                                        raise_missing=False, raise_not_set=False, print_missing=True)
    if asbool(enable_register_user):
        LOGGER.info("Adding user registration route.")
        config.add_route(**s.service_api_route_info(s.RegisterUsersAPI))
        # only admins can list pending users, but anyone can self-register for pending user approval
        config.add_view(rv.get_pending_users_view, route_name=s.RegisterUsersAPI.name, request_method="GET")
        config.add_view(rv.create_pending_user_view, route_name=s.RegisterUsersAPI.name, request_method="POST",
                        permission=NO_PERMISSION_REQUIRED)
    else:
        LOGGER.info("User registration disabled [setting MAGPIE_USER_REGISTRATION].")

    config.scan()
