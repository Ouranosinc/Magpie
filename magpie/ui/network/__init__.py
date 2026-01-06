from magpie.utils import fully_qualified_name, get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.ui.network.views import NetworkViews
    LOGGER.info("Adding UI network...")
    path = "/ui/network/authorize"
    config.add_route(fully_qualified_name(NetworkViews.authorize), path)
    config.scan()
