from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.ui.user.views import UserViews
    LOGGER.info("Adding UI user...")
    config.add_route(UserViews.edit_current_user.__name__, "/ui/users/current")
