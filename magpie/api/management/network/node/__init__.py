from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.api import schemas as s
    LOGGER.info("Adding API network node...")
    config.add_route(**s.service_api_route_info(s.NetworkNodesAPI))  # /network/nodes GET and POST
    config.add_route(**s.service_api_route_info(s.NetworkNodeAPI))  # /network/nodes/{node_name} GET, DELETE, PATCH
    config.add_route(**s.service_api_route_info(s.NetworkNodeTokenAPI))  # /network/nodes/{node_name}/token GET and DELETE
    config.add_route(**s.service_api_route_info(s.NetworkNodesLinkAPI))  # /network/nodes/link GET
    config.add_route(**s.service_api_route_info(s.NetworkNodeLinkAPI))  # /network/nodes/link POST

    config.scan()
