from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding API management routes...")
    config.include("magpie.api.management.group")
    config.include("magpie.api.management.user")
    config.include("magpie.api.management.service")
    config.include("magpie.api.management.resource")
    config.include("magpie.api.management.register")
    config.include("magpie.api.management.network_node")
    config.scan()
