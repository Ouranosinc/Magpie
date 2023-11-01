from magpie.constants import get_constant
from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding API management routes...")
    config.include("magpie.api.management.group")
    config.include("magpie.api.management.user")
    config.include("magpie.api.management.service")
    config.include("magpie.api.management.resource")
    config.include("magpie.api.management.register")
    if get_constant("MAGPIE_NETWORK_ENABLED", config):
        config.include("magpie.api.management.network")
    config.scan()
