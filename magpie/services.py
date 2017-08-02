from magpie import *
from owsrequest import *
from models import find_children_by_name


class ServiceI(object):
    permission_names = []
    param_values = []

    acl = []

    def __init__(self, service, request):
        self.service = service
        self.request = request

    @property
    def __acl__(self):
        raise NotImplementedError

    def expand_acl(self, resource, user):
        if resource:
            for ace in resource.__acl__:
                self.acl.append(ace)
            # Custom acl
            if user:
                permissions = resource.perms_for_user(user)
                for outcome, perm_user, perm_name in permission_to_pyramid_acls(permissions):
                    self.acl.append((outcome, perm_user, perm_name,))

    def permission_requested(self):
        raise NotImplementedError


class ServiceWPS(ServiceI):

    permission_names = ['getcapabilities',
                        'describeprocess',
                        'execute']

    params_expected = ['service',
                    'request',
                    'version']

    def __init__(self, service, request):
        super(ServiceWPS, self).__init__(service, request)
        self.parser = ows_parser_factory(request)
        self.parser.parse(self.params_expected)

    @property
    def __acl__(self):
        self.expand_acl(self.service, self.request.user)
        return self.acl

    def permission_requested(self):
        #should be in permission_types
        return self.parser.params['request']





class ServiceWMS(ServiceI):
    permission_names = ['getcapabilities',
                         'getmap',
                         'getfeatureinfo',
                         'getlegendgraphic',
                         'getmetadata']

    params_expected = ['service',
                    'request',
                    'version',
                    'layers']

    def __init__(self, service, request):
        super(ServiceWMS, self).__init__(service, request)
        self.parser = ows_parser_factory(request)
        self.parser.parse(self.params_expected)

    @property
    def __acl__(self):
        self.expand_acl(self.service, self.request.user)

        #localhost:8087/geoserver/WATERSHED/wms?layers=WATERSHED:BV_1NS&request=getmap
        #localhost:8087/geoserver/wms?layers=WATERERSHED:BV1_NS&request=getmap
        #those two request lead to the same thing so, here we need to check the workspace in the layer

        #localhost:8087/geoserver/wms?request=getcapabilities (dangerous, get all workspace)
        # localhost:8087/geoserver/WATERSHED/wms?request=getcapabilities (only for the workspace in the path)
        #here we need to check the workspace in the path


        request_type = self.permission_requested()
        if request_type == 'getcapabilities':
            path_elem = self.request.path.split('/')
            wms_idx = path_elem.index('wms')
            if path_elem[wms_idx-1] != 'geoserver':
                worskpace_name = path_elem[wms_idx-1]
            else:
                worskpace_name = ''
        else:
            layer_name = self.parser.params['layers']
            worskpace_name = layer_name.split(':')[0]

        #load workspace resource from the database
        workspace = find_children_by_name(name=worskpace_name,
                                          parent_id=self.service.resource_id,
                                          db_session=self.request.db)
        if workspace:
            self.expand_acl(workspace, self.request.user)
        return self.acl

    def permission_requested(self):
        # should be in permission_types
        return self.parser.params['request']


class ServiceWFS(object):
    permission_names = ['getcapabilities',
                        'describefeaturetype',
                        'getfeature',
                        'lockfeature',
                        'transaction']

    params_expected = ['service',
                       'request',
                       'version',
                       'typenames']

    def __init__(self, service, request):
        super(ServiceWMS, self).__init__(service, request)
        self.parser = ows_parser_factory(request)
        self.parser.parse(self.params_expected)

    @property
    def __acl__(self):
        self.expand_acl(self.service, self.request.user)
        request_type = self.permission_requested()
        if request_type == 'getcapabilities':
            path_elem = self.request.path.split('/')
            wms_idx = path_elem.index('wfs')
            if path_elem[wms_idx - 1] != 'geoserver':
                worskpace_name = path_elem[wms_idx - 1]
            else:
                worskpace_name = ''
        else:
            layer_name = self.parser.params['typenames']
            worskpace_name = layer_name.split(':')[0]

        # load workspace resource from the database
        workspace = find_children_by_name(name=worskpace_name,
                                          parent_id=self.service.resource_id,
                                          db_session=self.request.db)
        if workspace:
            self.expand_acl(workspace, self.request.user)
        return self.acl

    def permission_requested(self):
        # should be in permission_types
        return self.parser.params['request']


class ServiceTHREDDS(ServiceI):
    permission_names = ['download']

    def __init__(self, service, request):
        super(ServiceTHREDDS, self).__init__(service, request)


    @property
    def __acl__(self):
        self.expand_acl(self.service, self.request.user)
        elems = self.request.path.split('/')

        if 'fileServer' in elems:
            first_idx = elems.index('fileServer')
        elif 'dodsC' in elems:
            first_idx = elems.index('dodsC')
            elems[-1] = elems[-1].replace('.html', '')
        else:
            return self.acl

        elems = elems[first_idx+1::]
        db = self.request.db
        new_child = self.service
        while new_child and elems:
            name = elems.pop(0)
            new_child = find_children_by_name(name, parent_id=new_child.resource_id, db_session=db)
            self.expand_acl(new_child, self.request.user)

        return self.acl

    def permission_requested(self):
        # /thredds/fileServer
        # /thredds/dods
        # /thredds/{access_method}
        return 'download'

    pass


service_type_dico = {'wps': ServiceWPS,
                     'wms': ServiceWMS,
                     'wfs': ServiceWFS,
                     'thredds': ServiceTHREDDS}


def service_factory(service, request):
    try:
        service_specific = service_type_dico[service.type](service, request)
        return service_specific
    except:
        raise Exception('This type of service dows not exist')


def get_all_service_permission_names():
    all_permission_names_list = set()
    for service_type in service_type_dico.keys():
        all_permission_names_list.update(service_type_dico[service_type].permission_names)
    return all_permission_names_list
