from magpie import models
from magpie.register import SERVICES_PHOENIX_ALLOWED
from magpie.definitions.ziggurat_definitions import *
from magpie.services import service_type_dict
from magpie.api.api_except import *
from magpie.api.management.group.group_utils import create_group_resource_permission
import os


def get_services_by_type(service_type, db_session):
    verify_param(service_type, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `service_type` value '" + str(service_type) + "' specified")
    services = db_session.query(models.Service).filter(models.Service.type == service_type)
    return sorted(services)


def add_service_getcapabilities_perms(service, db_session, group_name=None):
    if service.type in SERVICES_PHOENIX_ALLOWED \
    and 'getcapabilities' in service_type_dict[service.type].permission_names:
        if group_name is None:
            group_name = os.getenv('ANONYMOUS_USER')
        group = GroupService.by_group_name(group_name, db_session=db_session)
        perm = ResourceService.perm_by_group_and_perm_name(service.resource_id, group.id,
                                                           u'getcapabilities', db_session)
        if perm is None:  # not set, create it
            create_group_resource_permission(u'getcapabilities', service, group, db_session)
