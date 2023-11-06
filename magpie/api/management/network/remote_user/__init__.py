from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.api import schemas as s
    LOGGER.info("Adding API network remote users ...")
    config.add_route(**s.service_api_route_info(s.NetworkRemoteUsersAPI))
    config.add_route(**s.service_api_route_info(s.NetworkRemoteUserAPI))
    config.add_route(**s.service_api_route_info(s.NetworkRemoteUsersCurrentAPI))

    config.scan()
