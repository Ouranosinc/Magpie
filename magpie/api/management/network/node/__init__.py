from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.api import schemas as s
    LOGGER.info("Adding API network node...")
    config.add_route(**s.service_api_route_info(s.NetworkNodesAPI))
    config.add_route(**s.service_api_route_info(s.NetworkNodeAPI))
    config.add_route(**s.service_api_route_info(s.NetworkNodeTokenAPI))
    config.add_route(**s.service_api_route_info(s.NetworkLinkAPI))
    config.add_route(**s.service_api_route_info(s.NetworkNodeLinkAPI))

    config.scan()
