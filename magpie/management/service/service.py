from magpie import *
import models


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
    try:
        db = request.db
        group_admin = GroupService.by_group_name(group_name='admin', db_session=db)
        if group_admin:
            service = models.Service(resource_name=service_name,
                                     resource_type='service',
                                     url=service_url,
                                     type=service_type,
                                     owner_group_id=group_admin.id)
        else:
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
        db.delete(service)
        db.commit()

    except:
        db.rollback()
        raise HTTPNotFound(detail="This service does not exist")

    return HTTPOk()


