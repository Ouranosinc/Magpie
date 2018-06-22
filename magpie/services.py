from magpie import *
from owsrequest import *
from definitions.ziggurat_definitions import *
from models import find_children_by_name
from pyramid.security import Everyone as EVERYONE
from pyramid.security import Allow
from api.api_except import *


class ServiceI(object):
    permission_names = []   # global permissions allowed for the service (top-level resource)
    params_expected = []    # derived services must have 'request' at least for 'permission_requested' method
    resource_types_permissions = {}     # dict of list for each corresponding allowed resource permissions

    # make 'property' getter from derived classes
    class __metaclass__(type):
        @property
        def resource_types(cls):  # allowed resources types under the service
            return cls.resource_types_permissions.keys()

    def __init__(self, service, request):
        self.service = service
        self.request = request
        self.acl = []
        self.parser = ows_parser_factory(request)
        self.parser.parse(self.params_expected)

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
            else:
                user = UserService.by_user_name(ANONYMOUS_USER, db_session=self.request.db)
                if user is None:
                    raise Exception('No Anonymous user in the database')
                else:
                    permissions = resource.perms_for_user(user)
                    for outcome, perm_user, perm_name in permission_to_pyramid_acls(permissions):
                        self.acl.append((outcome, EVERYONE, perm_name,))

    def permission_requested(self):
        try:
            return self.parser.params[u'request']
        except Exception as e:
            # if 'ServiceI', 'params_expected' is empty and will raise a KeyError
            raise NotImplementedError("Exception: [" + repr(e) + "]")


class ServiceWPS(ServiceI):

    permission_names = [
        u'getcapabilities',
        u'describeprocess',
        u'execute'
    ]

    params_expected = [
        u'service',
        u'request',
        u'version'
    ]

    resource_types_permissions = {}

    def __init__(self, service, request):
        super(ServiceWPS, self).__init__(service, request)

    @property
    def __acl__(self):
        self.expand_acl(self.service, self.request.user)
        return self.acl


class ServiceWMS(ServiceI):

    permission_names = [
        u'getcapabilities',
        u'getmap',
        u'getfeatureinfo',
        u'getlegendgraphic',
        u'getmetadata'
    ]

    params_expected = [
        u'service',
        u'request',
        u'version',
        u'layers',
        u'layername',
        u'dataset'
    ]

    resource_types_permissions = {
        models.Workspace.resource_type_name: [
            u'getcapabilities',
            u'getmap',
            u'getfeatureinfo',
            u'getlegendgraphic',
            u'getmetadata'
        ]
    }

    def __init__(self, service, request):
        super(ServiceWMS, self).__init__(service, request)

    @property
    def __acl__(self):
        raise NotImplementedError


class ServiceNCWMS2(ServiceWMS):

    resource_types_permissions = {
        models.File.resource_type_name: [
            u'getcapabilities',
            u'getmap',
            u'getfeatureinfo',
            u'getlegendgraphic',
            u'getmetadata'
        ],
        models.Directory.resource_type_name: [
            u'getcapabilities',
            u'getmap',
            u'getfeatureinfo',
            u'getlegendgraphic',
            u'getmetadata'
        ]
    }

    def __init__(self, service, request):
        super(ServiceNCWMS2, self).__init__(service, request)

    @property
    def __acl__(self):
        self.expand_acl(self.service, self.request.user)

        # According to the permission, the resource we want to authorize is not formatted the same way
        permission_requested = self.permission_requested()
        netcdf_file = None
        if permission_requested == 'getcapabilities':
            # https://colibri.crim.ca/twitcher/ows/proxy/ncWMS2/wms?SERVICE=WMS&REQUEST=GetCapabilities&VERSION=1.3.0&DATASET=outputs/ouranos/subdaily/aet/pcp/aet_pcp_1961.nc
            if 'dataset' in self.parser.params.keys():
                netcdf_file = self.parser.params['dataset']
            # replace output/ with birdhouse/

        elif permission_requested == 'getmap':
            # https://colibri.crim.ca/ncWMS2/wms?SERVICE=WMS&VERSION=1.3.0&REQUEST=GetMap&FORMAT=image%2Fpng&TRANSPARENT=TRUE&ABOVEMAXCOLOR=extend&STYLES=default-scalar%2Fseq-Blues&LAYERS=outputs/ouranos/subdaily/aet/pcp/aet_pcp_1961.nc/PCP&EPSG=4326
            netcdf_file = self.parser.params['layers']
            if netcdf_file:
                netcdf_file = netcdf_file.rsplit('/', 1)[0]

        elif permission_requested == 'getmetadata':
            # https://colibri.crim.ca/ncWMS2/wms?request=GetMetadata&item=layerDetails&layerName=outputs/ouranos/subdaily/aet/pcp/aet_pcp_1961.nc/PCP
            netcdf_file = self.parser.params['layername']
            if netcdf_file:
                netcdf_file = netcdf_file.rsplit('/', 1)[0]

        else:
            return [(Allow, EVERYONE, permission_requested,)]

        if netcdf_file:
            verify_param('outputs/', paramCompare=netcdf_file, httpError=HTTPNotFound,msgOnFail='outputs/ is not in path', notIn=True)
            netcdf_file = netcdf_file.replace('outputs/', 'birdhouse/')

            elems = netcdf_file.split('/')
            db = self.request.db
            new_child = self.service
            while new_child and elems:
                name = elems.pop(0)
                new_child = find_children_by_name(name, parent_id=new_child.resource_id, db_session=db)
                self.expand_acl(new_child, self.request.user)

        return self.acl


class ServiceGeoserver(ServiceWMS):

    def __init__(self, service, request):
        super(ServiceGeoserver, self).__init__(service, request)

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
                workspace_name = path_elem[wms_idx-1]
            else:
                workspace_name = ''
        else:
            layer_name = self.parser.params['layers']
            workspace_name = layer_name.split(':')[0]

        # load workspace resource from the database
        workspace = find_children_by_name(name=workspace_name,
                                          parent_id=self.service.resource_id,
                                          db_session=self.request.db)
        if workspace:
            self.expand_acl(workspace, self.request.user)
        return self.acl


class ServiceAPI(ServiceI):
    permission_names = models.Route.permission_names

    params_expected = []

    resource_types_permissions = {
        models.Route.resource_type_name: models.Route.permission_names
    }

    def __init__(self, service, request):
        super(ServiceAPI, self).__init__(service, request)

    @property
    def __acl__(self):
        raise NotImplementedError

    @property
    def route_acl(self, sub_api_route=None):
        self.expand_acl(self.service, self.request.user)

        route_parts = self.request.path.split('/')
        route_api_base = self.service.resource_name if sub_api_route is None else sub_api_route

        if self.service.resource_name in route_parts and route_api_base in route_parts:
            api_idx = route_parts.index(route_api_base)
            # keep only parts after api base route to process it
            if len(route_parts) - 1 > api_idx:
                route_parts = route_parts[api_idx + 1::]
                route_child = self.service
                while route_child and route_parts:
                    part_name = route_parts.pop(0)
                    route_res_id = route_child.resource_id
                    route_child = find_children_by_name(part_name, parent_id=route_res_id, db_session=self.request.db)
                    self.expand_acl(route_child, self.request.user)
        return self.acl

    def permission_requested(self):
        if self.request.method == 'GET':
            return u'read'
        return u'write'


class ServiceGeoserverAPI(ServiceAPI):
    def __init__(self, service, request):
        super(ServiceGeoserverAPI, self).__init__(service, request)

    @property
    def __acl__(self):
        return ServiceAPI.route_acl.fget(self)


class ServiceProjectAPI(ServiceAPI):
    def __init__(self, service, request):
        super(ServiceProjectAPI, self).__init__(service, request)

    @property
    def __acl__(self):
        return ServiceAPI.route_acl.fget(self, sub_api_route='api')


class ServiceWFS(ServiceI):

    permission_names = [
        u'getcapabilities',
        u'describefeaturetype',
        u'getfeature',
        u'lockfeature',
        u'transaction'
    ]

    params_expected = [
        u'service',
        u'request',
        u'version',
        u'typenames'
    ]

    resource_types_permissions = {}

    def __init__(self, service, request):
        super(ServiceWFS, self).__init__(service, request)

    @property
    def __acl__(self):
        self.expand_acl(self.service, self.request.user)
        request_type = self.permission_requested()
        if request_type == 'getcapabilities':
            path_elem = self.request.path.split('/')
            wms_idx = path_elem.index('wfs')
            if path_elem[wms_idx - 1] != 'geoserver':
                workspace_name = path_elem[wms_idx - 1]
            else:
                workspace_name = ''
        else:
            layer_name = self.parser.params['typenames']
            workspace_name = layer_name.split(':')[0]

        # load workspace resource from the database
        workspace = find_children_by_name(name=workspace_name,
                                          parent_id=self.service.resource_id,
                                          db_session=self.request.db)
        if workspace:
            self.expand_acl(workspace, self.request.user)
        return self.acl


class ServiceTHREDDS(ServiceI):

    permission_names = [
        u'read',
        u'write'
    ]

    params_expected = [
        u'request'
    ]

    resource_types_permissions = {
        models.Directory.resource_type_name: [
            u'read',
            u'write'
        ],
        models.File.resource_type_name: [
            u'read',
            u'write'
        ],
    }

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
        elif 'catalog' in elems:
            first_idx = elems.index('catalog')
        elif elems[-1] == 'catalog.html':
            first_idx = elems.index(self.service.resource_name) - 1
        else:
            return self.acl

        elems = elems[first_idx+1::]
        db = self.request.db
        new_child = self.service
        while new_child and elems:
            name = elems.pop(0)
            if ".nc" in name:
                name = name.split(".nc")[0]+".nc"  #in case there is more extension to discard such as .dds
            new_child = find_children_by_name(name, parent_id=new_child.resource_id, db_session=db)
            self.expand_acl(new_child, self.request.user)

        return self.acl

    def permission_requested(self):
        return u'read'


service_type_dict = {
    u'geoserver-api':   ServiceGeoserverAPI,
    u'geoserverwms':    ServiceGeoserver,
    u'ncwms':           ServiceNCWMS2,
    u'project-api':     ServiceProjectAPI,
    u'thredds':         ServiceTHREDDS,
    u'wfs':             ServiceWFS,
    u'wps':             ServiceWPS,
}


def service_factory(service, request):
    verify_param(service, ofType=models.Service, httpError=HTTPBadRequest, content={u'service': repr(service)},
                 msgOnFail="Cannot process invalid service object")
    service_type = evaluate_call(lambda: service.type, httpError=HTTPInternalServerError,
                                 msgOnFail="Cannot retrieve service type from object")
    verify_param(service_type, isIn=True, paramCompare=service_type_dict.keys(), httpError=HTTPNotImplemented,
                 msgOnFail="Undefined service type mapping to service object", content={u'service_type': service_type})
    return evaluate_call(lambda: service_type_dict[service_type](service, request), httpError=HTTPInternalServerError,
                         msgOnFail="Failed to find requested service type.")


def get_all_service_permission_names():
    all_permission_names_list = set()
    for service_type in service_type_dict.keys():
        all_permission_names_list.update(service_type_dict[service_type].permission_names)
    return all_permission_names_list
