from magpie.utils import get_logger
LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding api routes...")

    # Add all the admin ui routes
    config.include("magpie.api.home")
    config.include("magpie.api.login")
    config.include("magpie.api.management")
