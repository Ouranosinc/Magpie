from magpie import *
from owsrequest import *


class ServiceI(object):
    permission_types = []
    param_values = []

    acl = []

    def __init__(self, service, request):
        self.service = service
        self.request = request

    @property
    def __acl__(self):
        raise NotImplementedError

    def expand_acl(self, resource, user):
        for ace in resource.__acl__:
            self.acl.append(ace)
        # Custom acl
        permissions = resource.perms_for_user(user)
        for outcome, perm_user, perm_name in permission_to_pyramid_acls(permissions):
            self.acl.append((outcome, perm_user, perm_name,))

    def permission_requested(self):
        raise NotImplementedError


class ServiceWPS(ServiceI):

    permission_types = ['getcapabilities',
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



'''

class ServiceWMS(object):
    permission_types = ['getcapabilities',
                         'getmap',
                         'getfeatureinfo',
                         'getlegendgraphic',
                         'getmetadata']

    param_values = ['service',
                    'request',
                    'version',
                    'layers']

    def permission_requested(self, http_request):
        return self.parser.params['request']

    def get_workspace(self):
        #should be the same infront befor prefix and in the path
        # geoserver/WATERSHED
        # layers=WATHERSHED:BV_N1_S
        return workspace_name


    def __init__(self, service):
        self.service = service
        self.parser = ows_parser_factory(request)
        self.parser.parse()
        self.init_acl() #modify the acl

    def extend_acl(self,resource):
        self.__acl__.append(resource.__acl__)
        permissions = self.perms_for_user(self.request.user)
        for outcome, perm_user, perm_name in permission_to_pyramid_acls(permissions):
            self.__acl__.append((outcome, perm_user, perm_name,))

        # you need to add WORKSPACE ACL !
    def init_acl(self):
        self.acl = self.service.acl
        self.extend_acl(self.service)
        workspace_name = self.parser.params['workspace']
        tree = tree_structure(self.service.resource_id)
        workspace_resource = go_1level_in_the_children_and_find_WorkspaceName
        self.extend_acl(workspace_resource)





class ServiceWFS(object):
    permission_types = ['getcapabilities',
                        'DescribeFeatureType',
                        'GetFeature',
                        'LockFeature',
                        'Transaction']

    pass


class ServiceTHREDDS(object):
    permission_types = ['fileserver',
                        'dods']

    def permission_requested(self, http_request):
        # /thredds/fileServer
        # /thredds/dods
        # /thredds/{access_method}

        return  access_method

    def init_acl(self):
        #Use traversal or treestructure
        # maketree_from(self.service.id)
        # /thredds/fileServer/*traversal
        # go deep in the three
        # for resource_name in traversal:
        #
        #   extend_acl(resource)
        #


    pass

'''

service_type_dico = {'wps': ServiceWPS}

def service_factory(service, request):
    try:
        service_specific = service_type_dico[service.type](service, request)
        return service_specific
    except:
        raise Exception('This type of service dows not exist')


