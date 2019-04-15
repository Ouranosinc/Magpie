from magpie.utils import get_logger
LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding login...")
    config.add_route("login", "/ui/login")
    config.add_route("logout", "/ui/logout")
    config.add_route("register", "/ui/register")
    config.scan()
