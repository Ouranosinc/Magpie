from pyramid.httpexceptions import exception_response

import logging
logger = logging.getLogger(__name__)


def check_res(response):
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)
    return response


def includeme(config):

    logger.info('Adding management ...')
    config.add_route('view_groups', '/groups')
    config.add_route('add_group', '/groups/add')
    config.add_route('edit_group', '/groups/{group_name}/{cur_svc_type}')
    config.add_route('view_users', '/users')
    config.add_route('add_user', '/users/add')
    config.add_route('edit_user', '/users/{user_name}')
    config.add_route('view_services', '/services/{cur_svc_type}')
    config.add_route('add_service', '/services/{cur_svc_type}/add')
    config.add_route('edit_service', '/services/{cur_svc_type}/{service_name}')
    config.add_route('add_resource', '/services/{cur_svc_type}/{service_name}/add/{resource_id}')
    config.scan()
