from pyramid.settings import asbool

from magpie.constants import get_constant
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.ui.management.views import ManagementViews
    LOGGER.info("Adding UI management...")
    config.add_route(ManagementViews.view_groups.__name__,
                     "/ui/groups")
    config.add_route(ManagementViews.add_group.__name__,
                     "/ui/groups/add")
    config.add_route(ManagementViews.edit_group.__name__,
                     "/ui/groups/{group_name}/{cur_svc_type}")
    config.add_route(ManagementViews.view_users.__name__,
                     "/ui/users")
    config.add_route(ManagementViews.add_user.__name__,
                     "/ui/users/add")
    config.add_route(ManagementViews.edit_user.__name__,
                     "/ui/users/{user_name}/{cur_svc_type}")
    config.add_route(ManagementViews.view_services.__name__,
                     "/ui/services/{cur_svc_type}")
    config.add_route(ManagementViews.add_service.__name__,
                     "/ui/services/{cur_svc_type}/add")
    config.add_route(ManagementViews.edit_service.__name__,
                     "/ui/services/{cur_svc_type}/{service_name}")
    config.add_route(ManagementViews.add_resource.__name__,
                     "/ui/services/{cur_svc_type}/{service_name}/add/{resource_id}")

    register_user_enabled = asbool(get_constant("MAGPIE_USER_REGISTRATION_ENABLED", settings_container=config,
                                                default_value=False, print_missing=True,
                                                raise_missing=False, raise_not_set=False))
    if register_user_enabled:
        LOGGER.info("Adding UI pending user registration detail page.")
        config.add_route("view_pending_user", "/ui/register/users/{user_name}")
        config.add_view(ManagementViews, attr="view_pending_user", route_name="view_pending_user",
                        renderer="magpie.ui.management:templates/view_pending_user.mako")

    config.scan()
