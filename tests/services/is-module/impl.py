from magpie.services import ServiceInterface


class DynamicServiceFromIsModule(ServiceInterface):
    service_type = 'DynamicServiceFromIsModule'

    def __req__(self, request):
        return {'body': 'ok'}

    @property
    def __acl__(self):
        return [('Allow', 1, 'perm')]
