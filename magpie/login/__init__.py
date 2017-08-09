import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding login ...')
    # Add all the rest api routes
    config.add_route('session', '/session')
    config.add_route('signin', '/signin')
    config.add_route('signout', '/signout')
    config.add_route('providers', '/providers')
    config.add_route('external_login', 'providers/{provider_name}/signin')
    config.add_route('successful_operation', '/successful_operation')
    config.scan()
