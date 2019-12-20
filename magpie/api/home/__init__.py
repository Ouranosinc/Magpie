from magpie.api import schemas as s
from magpie.api.home.home import get_homepage
from magpie.constants import get_constant
from pyramid.security import NO_PERMISSION_REQUIRED
from magpie.utils import get_logger
LOGGER = get_logger(__name__)


def includeme(config):
    LOGGER.info("Adding API base routes...")
    config.add_route(**s.service_api_route_info(s.VersionAPI))
    if not get_constant("MAGPIE_UI_ENABLED"):
        LOGGER.info("Adding API homepage...")
        config.add_route(s.HomepageAPI.name, s.HomepageAPI.path)
        config.add_view(get_homepage, route_name=s.HomepageAPI.name, permission=NO_PERMISSION_REQUIRED)
    config.scan()
