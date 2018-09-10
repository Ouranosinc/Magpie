from magpie.api.api_generic import not_found, internal_server_error, unauthorized_access
import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding api routes ...')

    # Add all the admin ui routes
    config.include('magpie.api.esgf')
    config.include('magpie.api.home')
    config.include('magpie.api.login')
    config.include('magpie.api.management')

    config.add_notfound_view(not_found)
    config.add_exception_view(internal_server_error)
    config.add_forbidden_view(unauthorized_access)
    #config.scan()
