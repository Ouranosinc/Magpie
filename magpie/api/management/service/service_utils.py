from magpie import models
from magpie.constants import get_constant
from magpie.register import SERVICES_PHOENIX_ALLOWED
from magpie.definitions.ziggurat_definitions import *
from magpie.services import service_type_dict
from magpie.api.api_except import *
from magpie.api.management.group.group_utils import create_group_resource_permission


def create_service(service_name, service_type, service_url, db_session):
    """Generates an instance to register a new service."""
    # noinspection PyArgumentList
    return evaluate_call(lambda: models.Service(resource_name=str(service_name),
                                                resource_type=models.Service.resource_type_name,
                                                url=str(service_url), type=str(service_type)),
                         fallback=lambda: db_session.rollback(), httpError=HTTPForbidden,
                         msgOnFail="Service creation for registration failed.",
                         content={u'service_name': str(service_name),
                                  u'resource_type': models.Service.resource_type_name,
                                  u'service_url': str(service_url), u'service_type': str(service_type)})


def get_services_by_type(service_type, db_session):
    verify_param(service_type, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `service_type` value '" + str(service_type) + "' specified")
    services = db_session.query(models.Service).filter(models.Service.type == service_type)
    return sorted(services)


def add_service_getcapabilities_perms(service, db_session, group_name=None):
    if service.type in SERVICES_PHOENIX_ALLOWED \
    and 'getcapabilities' in service_type_dict[service.type].permission_names:
        if group_name is None:
            group_name = get_constant('MAGPIE_ANONYMOUS_USER')
        group = GroupService.by_group_name(group_name, db_session=db_session)
        perm = ResourceService.perm_by_group_and_perm_name(service.resource_id, group.id,
                                                           u'getcapabilities', db_session)
        if perm is None:  # not set, create it
            create_group_resource_permission(u'getcapabilities', service, group, db_session)
