from magpie.utils import get_logger

LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding UI home...")
    config.add_route("home", "/")
    config.add_route("home_ui", "/ui")
    config.add_route("error", "/ui/error")
    config.add_static_view("static", "static", cache_max_age=3600)
    config.scan()
