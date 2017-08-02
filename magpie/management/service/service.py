from magpie import *
import models
from models import resource_tree_service
from management.service.resource import *

@view_config(route_name='services', request_method='GET')
def get_services(request):
    service_names = [service.resource_name for service in models.Service.all(db_session=request.db)]
    json_response = {'service_names': service_names}
    return HTTPOk(
        body=json.dumps(json_response),
        content_type='application/json'
    )


@view_config(route_name='services', request_method='POST')
def register_service(request):
    service_name = request.POST.get('service_name')
    service_url = request.POST.get('service_url')
    service_type = request.POST.get('service_type')
    db = request.db
    if models.Service.by_service_name(service_name, db_session=db):
        raise HTTPConflict(detail='This service name is already used')
    try:
        service = models.Service(resource_name=service_name,
                                 resource_type='service',
                                 url=service_url,
                                 type=service_type)

        db.add(service)
        db.commit()
    except:
        db.rollback()
        raise HTTPConflict(detail='Bad input:service_name|service_url|service_type')

    return HTTPCreated()


@view_config(route_name='service', request_method='GET')
def get_service(request):
    service_name = request.matchdict.get('service_name')
    service = models.Service.by_service_name(service_name, db_session=request.db)

    if service:
        json_response = {'service_name': service.resource_name,
                         'service_type': service.type,
                         'service_url': service.url}

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
        db.commit()

    except:
        db.rollback()
        raise HTTPNotFound(detail="This service does not exist")

    return HTTPOk()


from services import service_type_dico
@view_config(route_name='service_permissions', request_method='GET')
def get_service_permissions(request):
    service_name = request.matchdict.get('service_name')
    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    if service:
        try:
            service_permissions = service_type_dico[service.type].permission_names
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


@view_config(route_name='service_resources', request_method='GET')
def get_service_resources(request):
    service_name = request.matchdict.get('service_name')
    db = request.db
    service = models.Service.by_service_name(service_name, db_session=db)
    if not service:
        raise HTTPNotFound(detail='This service does not exist')
    tree_struct = resource_tree_service.from_parent_deeper(service.resource_id, db_session=db)

    resource_info_dict={}
    for node in tree_struct:
        resource_id = node.Resource.resource_id
        resource_info = get_resource_info(resource_id, db_session=db)
        resource_info_dict[resource_id] = resource_info


    return HTTPOk(
        body=json.dumps({'resources': resource_info_dict}),
        content_type='application/json'
    )


@view_config(route_name='service_resources', request_method='POST')
def create_service_direct_resource(request):
    service_name = request.matchdict.get('service_name')
    resource_name = request.POST.get('resource_name')
    resource_type = request.POST.get('resource_type')
    service = models.Service.by_service_name(service_name, db_session=request.db)
    if service:
        return create_resource(resource_name, resource_type, service.resource_id, db_session=request.db)
    else:
        raise HTTPNotFound(detail='Bad entry: service_name or service_type')
