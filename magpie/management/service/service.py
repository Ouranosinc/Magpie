from magpie import *
import models
from models import resource_tree_service
from services import service_type_dict
from management.service.resource import *


def format_service(service, perms=None):
    return {
        u'service_url': str(service.url),
        u'service_name': str(service.resource_name),
        u'service_type': str(service.type),
        u'resource_id': service.resource_id,
        u'permission_names': list() if perms is None else perms
    }


def get_services_by_type(service_type, db_session):
    verify_param(service_type, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `service_type` value '" + str(service_type) + "' specified")
    services = db_session.query(models.Service).filter(models.Service.type == service_type)
    return services


@view_config(route_name='services_type', request_method='GET')
@view_config(route_name='services', request_method='GET')
def get_services_view(request):
    service_type = request.matchdict.get('service_type')
    json_response = {}
    if not service_type:
        service_types = [s for s in service_type_dict.keys()]
    else:
        service_types = [service_type]

    for service_type in service_types:
        services = get_services_by_type(service_type, db_session=request.db)
        json_response[service_type] = {}
        for service in services:
            json_response[service_type][service.resource_name] = format_service(service)

    return valid_http(httpSuccess=HTTPOk, detail="Get services successful", content={u'services': json_response})


@view_config(route_name='services', request_method='POST')
def register_service(request):
    service_name = get_multiformat_post(request, 'service_name')
    service_url = get_multiformat_post(request, 'service_url')
    service_type = get_multiformat_post(request, 'service_type')
    verify_param(service_name, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `service_name` value '" + str(service_name) + "' specified for registration")
    verify_param(service_url, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `service_url` value '" + str(service_url) + "' specified for registration")
    verify_param(service_type, notNone=True, notEmpty=True, httpError=HTTPNotAcceptable,
                 msgOnFail="Invalid `service_type` value '" + str(service_type) + "' specified for registration")
    verify_param(service_type, isIn=True, httpError=HTTPNotAcceptable, paramCompare=service_type_dict.keys(),
                 msgOnFail="Specified `service_type` value does not correspond to any of the available types")
    verify_param(service_name, notIn=True, httpError=HTTPConflict,
                 paramCompare=[models.Service.by_service_name(service_name, db_session=request.db)],
                 msgOnFail="Specified `service_name` value '" + str(service_name) + "' already exists")

    service = models.Service(resource_name=str(service_name),
                             resource_type=u'service',
                             url=str(service_url),
                             type=str(service_type))
    evaluate_call(lambda: request.db.add(service), fallback=lambda: request.db.rollback(), httpError=HTTPForbidden,
                  msgOnFail="Service registration forbidden by db", content=format_service(service))
    return valid_http(httpSuccess=HTTPCreated, detail="Service registration to db successful",
                      content=format_service(service))


@view_config(route_name='service', request_method='GET')
def get_service(request):
    service_name = request.matchdict.get('service_name')
    service = models.Service.by_service_name(service_name, db_session=request.db)
    json_response = {}
    if service:
        json_response[service.resource_name] = format_service(service)
        return HTTPOk(
            body=json.dumps(json_response),
            content_type='application/json'
        )
    else:
        return HTTPNotFound(detail="This service does not exist")


@view_config(route_name='service', request_method='DELETE')
def unregister_service(request):
    service_name = request.matchdict.get('service_name')
    try:
        db = request.db
        service = models.Service.by_service_name(service_name, db_session=db)
        resource_tree_service.delete_branch(resource_id=service.resource_id, db_session=db)
        db.delete(service)
        

    except:
        db.rollback()
        raise HTTPNotFound(detail="This service does not exist")

    return HTTPOk()


@view_config(route_name='service', request_method='PUT')
def update_service(request):
    service_name = get_multiformat_post(request, 'service_name')
    service_url = get_multiformat_post(request, 'service_url')
    db = request.db
    if service_name is None:
        raise HTTPBadRequest(detail='the service_name is missing')
    try:
        service = models.Service.by_service_name(service_name, db_session=db)
        service.url = service_url
    except Exception:
        db.rollback()
        raise HTTPNotFound('incorrect service_name')

    return HTTPOk()


@view_config(route_name='service_permissions', request_method='GET')
def get_service_permissions(request):
    service_name = request.matchdict.get('service_name')
    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    if service:
        try:
            service_permissions = service_type_dict[service.type].permission_names
        except:
            db.rollback()
            raise HTTPNotFound(detail="This type of service is not implemented yet")
    else:
        db.rollback()
        raise HTTPNotFound(detail="This service does not exist")

    return HTTPOk(
        body=json.dumps({'permission_names': service_permissions}),
        content_type='application/json'
    )


def format_service_resources(service,
                             db_session,
                             service_perms=[],
                             resources_perms_dict={},
                             display_all=False):

    tree = get_resource_children(service, db_session)
    if not display_all:
        tree, resource_id_list_remain = crop_tree_with_permission(tree,
                                                                  resources_perms_dict.keys())

    service_resources_formatted = format_service(service, service_perms)
    service_resources_formatted[u'resources'] = format_resource_tree(tree,
                                                                     resources_perms_dict=resources_perms_dict,
                                                                     db_session=db_session)
    return service_resources_formatted


@view_config(route_name='service_resources', request_method='GET')
def get_service_resources_view(request):
    service_name = request.matchdict.get('service_name')
    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    if not service:
        raise HTTPNotFound(detail='This service does not exist')

    json_response = format_service_resources(service, db_session=db, display_all=True)
    return HTTPOk(
        body=json.dumps({service.resource_name: json_response}),
        content_type='application/json'
    )


@view_config(route_name='service_resources', request_method='POST')
def create_service_direct_resource(request):
    service_name = request.matchdict.get('service_name')
    resource_name = get_multiformat_post(request, 'resource_name')
    resource_type = get_multiformat_post(request, 'resource_type')
    parent_id = get_multiformat_post(request, 'parent_id')
    service = models.Service.by_service_name(service_name, db_session=request.db)
    if service:

        if not parent_id:
            parent_id = service.resource_id
        return create_resource(resource_name, resource_type, parent_id=parent_id, db_session=request.db)
    else:
        raise HTTPNotFound(detail='Bad entry: service_name or service_type')



@view_config(route_name='resources', request_method='GET')
def get_resources_view(request):
    json_response = {}
    for service_type in service_type_dict.keys():
        services = get_services_by_type(service_type, db_session=request.db)
        json_response[service_type] = {}
        for service in services:
            json_response[service_type][service.resource_name] = format_service_resources(service,
                                                                                          db_session=request.db,
                                                                                          display_all=True)
    json_response = {'resource_types': [key for key in resource_type_dict.keys()],
                     'resources': json_response}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='service_type_resource_types', request_method='GET')
def get_service_type_resource_types(request):
    service_type = request.matchdict.get('type_name')
    if service_type in service_type_dict:
        resource_types = service_type_dict[service_type].resource_types
        return HTTPOk(
            body=json.dumps({'resource_types': resource_types}),
            content_type='application/json'
        )
    else:
        raise HTTPNotFound(detail='service type not found')
