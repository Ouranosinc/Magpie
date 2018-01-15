from pyramid.httpexceptions import exception_response

import logging
logger = logging.getLogger(__name__)


def check_response(response):
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)
    return response


def includeme(config):

    logger.info('Adding management ...')
    config.add_route('view_groups', '/ui/groups')
    config.add_route('add_group', '/ui/groups/add')
    config.add_route('edit_group', '/ui/groups/{group_name}/{cur_svc_type}')
    config.add_route('view_users', '/ui/users')
    config.add_route('add_user', '/ui/users/add')
    config.add_route('edit_user', '/ui/users/{user_name}')
    config.add_route('view_services', '/ui/services/{cur_svc_type}')
    config.add_route('add_service', '/ui/services/{cur_svc_type}/add')
    config.add_route('edit_service', '/ui/services/{cur_svc_type}/{service_name}')
    config.add_route('add_resource', '/ui/services/{cur_svc_type}/{service_name}/add/{resource_id}')
    config.scan()
