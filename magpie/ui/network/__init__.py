from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.ui.network.views import NetworkViews
    LOGGER.info("Adding UI network...")
    path = "/ui/network/authorize"
    config.add_route(NetworkViews.authorize.__name__, path)
    config.scan()
