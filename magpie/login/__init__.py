import logging
logger = logging.getLogger(__name__)



def includeme(config):
    settings = config.registry.settings

    logger.info('Adding login ...')
    # Add all the rest api routes
    config.add_route('session', '/session')
    config.add_route('signin', '/signin')
    config.add_route('signout', '/signout')
    config.add_route('external_login', 'providers/{provider_name}/signin')
    config.scan()
