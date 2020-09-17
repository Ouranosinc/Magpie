from magpie.constants import get_constant
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.ui.user.views import UserViews
    LOGGER.info("Adding UI user...")
    path = "/ui/users/{}".format(get_constant("MAGPIE_LOGGED_USER"))
    config.add_route(UserViews.edit_current_user.__name__, path)
    config.scan()
