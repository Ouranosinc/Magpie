import logging
logger = logging.getLogger(__name__)


def includeme(config):
    logger.info('Adding group ...')
    # Add all the rest api routes
    config.add_route('groups', '/groups')
    config.add_route('group', '/groups/{group_name}')
    config.add_route('group_users', '/groups/{group_name}/users')

    config.scan()
