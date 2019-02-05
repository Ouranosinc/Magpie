import logging
logger = logging.getLogger(__name__)


def includeme(config):
    from magpie.ui.management.views import ManagementViews
    logger.info('Adding management ...')
    config.add_route(ManagementViews.view_groups.__name__, '/ui/groups')
    config.add_route(ManagementViews.add_group.__name__, '/ui/groups/add')
    config.add_route(ManagementViews.edit_group.__name__, '/ui/groups/{group_name}/{cur_svc_type}')
    config.add_route(ManagementViews.view_users.__name__, '/ui/users')
    config.add_route(ManagementViews.add_user.__name__, '/ui/users/add')
    config.add_route(ManagementViews.edit_user.__name__, '/ui/users/{user_name}/{cur_svc_type}')
    config.add_route(ManagementViews.view_services.__name__, '/ui/services/{cur_svc_type}')
    config.add_route(ManagementViews.add_service.__name__, '/ui/services/{cur_svc_type}/add')
    config.add_route(ManagementViews.edit_service.__name__, '/ui/services/{cur_svc_type}/{service_name}')
    config.add_route(ManagementViews.add_resource.__name__, '/ui/services/{cur_svc_type}/{service_name}/add/{resource_id}')
    config.scan()
