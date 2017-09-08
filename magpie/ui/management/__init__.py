from pyramid.httpexceptions import exception_response

import logging
logger = logging.getLogger(__name__)


def check_res(response):
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)


def includeme(config):

    logger.info('Adding management ...')
    config.add_route('view_groups', '/groups')
    config.add_route('edit_group', '/groups/{group_name}/{cur_svc_type}')
    config.add_route('view_users', '/users')
    config.add_route('edit_user', '/users/{user_name}')
    config.add_route('service_manager', '/service_manager')
    config.add_static_view('static', 'static', cache_max_age=3600)
    config.scan()
