import logging
logger = logging.getLogger(__name__)


def includeme(config):

    logger.info('Adding user ...')
    # Add all the rest api routes
    config.add_route('users', '/users')
    config.add_route('user', '/users/{user_name}')
    config.add_route('user_groups', 'users/{user_name}/groups')
    config.add_route('user_group', '/users/{user_name}/groups/{group_name}')



    config.scan()
