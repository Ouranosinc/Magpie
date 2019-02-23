from magpie.services import ServiceInterface


class DynamicServiceFromNoModule(ServiceInterface):
    service_type = 'DynamicServiceFromNoModule'

    def __req__(self, request):
        return {'body': 'ok'}

    @propertyDynamicServiceFromNonModule
    def __acl__(self):
        return [('Allow', 1, 'perm')]
