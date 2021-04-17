from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding UI login...")
    config.add_route("login", "/ui/login")
    config.add_route("logout", "/ui/logout")
    config.add_route("register_user", "/ui/register")
    config.scan()
