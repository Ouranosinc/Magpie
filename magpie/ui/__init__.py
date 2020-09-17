from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding UI routes...")

    # Add all the admin ui routes
    config.include("magpie.ui.home")
    config.include("magpie.ui.login")
    config.include("magpie.ui.management")
    config.include("magpie.ui.user")
