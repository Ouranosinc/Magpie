from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    from magpie.api import schemas as s
    LOGGER.info("Adding API network remote users ...")
    config.add_route(**s.service_api_route_info(s.NetworkRemoteUsersAPI))  # /network/remote_users GET and POST
    config.add_route(**s.service_api_route_info(s.NetworkRemoteUserAPI))  # /network/remote_users/{remote_user_name} GET, DELETE, PATCH
    config.add_route(**s.service_api_route_info(s.NetworkRemoteUsersCurrentAPI))  # /network/remote_users/current GET

    config.scan()
