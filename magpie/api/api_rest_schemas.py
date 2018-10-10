from magpie.definitions.cornice_definitions import *
from magpie.definitions.pyramid_definitions import *
from magpie.constants import (
    MAGPIE_LOGGED_USER,
    MAGPIE_USER_NAME_MAX_LENGTH,
    MAGPIE_ADMIN_PERMISSION,
    MAGPIE_DEFAULT_PROVIDER
)
from magpie import __meta__
import six


TitleAPI = "Magpie REST API"
InfoAPI = {
    "description": __meta__.__description__,
    "contact": {"name": __meta__.__maintainer__, "email": __meta__.__email__, "url": __meta__.__url__}
}


# Tags
APITag = 'API'
LoginTag = 'Login'
UsersTag = 'User'
LoggedUserTag = 'Logged User'
GroupsTag = 'Group'
ResourcesTag = 'Resource'
ServicesTag = 'Service'


# Security
SecurityCookieAuthAPI = {'cookieAuth': {'type': 'apiKey', 'in': 'cookie', 'name': 'auth_tkt'}}
SecurityDefinitionsAPI = {'securityDefinitions': SecurityCookieAuthAPI}
SecurityAdministratorAPI = [{'cookieAuth': []}]
SecurityEveryoneAPI = [{}]


def get_security(service, method):
    definitions = service.definitions
    args = {}
    for definition in definitions:
        met, view, args = definition
        if met == method:
            break
    # automatically retrieve permission if specified within the view definition
    permission = args.get('permission')
    if permission == NO_PERMISSION_REQUIRED:
        return SecurityEveryoneAPI
    elif permission == MAGPIE_ADMIN_PERMISSION:
        return SecurityAdministratorAPI
    # return default admin permission otherwise unless specified form cornice decorator
    return SecurityAdministratorAPI if 'security' not in args else args['security']


# Service Routes
def service_api_route_info(service_api):
    return {'name': service_api.name, 'pattern': service_api.path}


LoggedUserBase = '/users/{}'.format(MAGPIE_LOGGED_USER)


SwaggerGenerator = Service(
    path='/json',
    name='swagger_schema_json')
SwaggerAPI = Service(
    path='/api',
    name='swagger_schema_ui',
    description="{} documentation".format(TitleAPI))
UsersAPI = Service(
    path='/users',
    name='Users')
UserAPI = Service(
    path='/users/{user_name}',
    name='User')
UserGroupsAPI = Service(
    path='/users/{user_name}/groups',
    name='UserGroups')
UserGroupAPI = Service(
    path='/users/{user_name}/groups/{group_name}',
    name='UserGroup')
UserInheritedResourcesAPI = Service(
    path='/users/{user_name}/inherited_resources',
    name='UserInheritedResources')
UserResourcesAPI = Service(
    path='/users/{user_name}/resources',
    name='UserResources')
UserResourceInheritedPermissionsAPI = Service(
    path='/users/{user_name}/resources/{resource_id}/inherited_permissions',
    name='UserResourceInheritedPermissions')
UserResourcePermissionAPI = Service(
    path='/users/{user_name}/resources/{resource_id}/permissions/{permission_name}',
    name='UserResourcePermission')
UserResourcePermissionsAPI = Service(
    path='/users/{user_name}/resources/{resource_id}/permissions',
    name='UserResourcePermissions')
UserResourceTypesAPI = Service(
    path='/users/{user_name}/resources/types/{resource_type}',
    name='UserResourceTypes')
UserInheritedServicesAPI = Service(
    path='/users/{user_name}/inherited_services',
    name='UserInheritedServices')
UserServicesAPI = Service(
    path='/users/{user_name}/services',
    name='UserServices')
UserServiceAPI = Service(
    path='/users/{user_name}/services/{service_name}',
    name='UserService')
UserServiceInheritedResourcesAPI = Service(
    path='/users/{user_name}/services/{service_name}/inherited_resources',
    name='UserServiceInheritedResources')
UserServiceResourcesAPI = Service(
    path='/users/{user_name}/services/{service_name}/resources',
    name='UserServiceResources')
UserServiceInheritedPermissionsAPI = Service(
    path='/users/{user_name}/services/{service_name}/inherited_permissions',
    name='UserServiceInheritedPermissions')
UserServicePermissionsAPI = Service(
    path='/users/{user_name}/services/{service_name}/permissions',
    name='UserServicePermissions')
UserServicePermissionAPI = Service(
    path='/users/{user_name}/services/{service_name}/permissions/{permission_name}',
    name='UserServicePermission')
LoggedUserAPI = Service(
    path=LoggedUserBase,
    name='LoggedUser')
LoggedUserGroupsAPI = Service(
    path=LoggedUserBase + '/groups',
    name='LoggedUserGroups')
LoggedUserGroupAPI = Service(
    path=LoggedUserBase + '/groups/{group_name}',
    name='LoggedUserGroup')
LoggedUserInheritedResourcesAPI = Service(
    path=LoggedUserBase + '/inherited_resources',
    name='LoggedUserInheritedResources')
LoggedUserResourcesAPI = Service(
    path=LoggedUserBase + '/resources',
    name='LoggedUserResources')
LoggedUserResourceInheritedPermissionsAPI = Service(
    path=LoggedUserBase + '/resources/{resource_id}/inherited_permissions',
    name='LoggedUserResourceInheritedPermissions')
LoggedUserResourcePermissionAPI = Service(
    path=LoggedUserBase + '/resources/{resource_id}/permissions/{permission_name}',
    name='LoggedUserResourcePermission')
LoggedUserResourcePermissionsAPI = Service(
    path=LoggedUserBase + '/resources/{resource_id}/permissions',
    name='LoggedUserResourcePermissions')
LoggedUserResourceTypesAPI = Service(
    path=LoggedUserBase + '/resources/types/{resource_type}',
    name='LoggedUserResourceTypes')
LoggedUserInheritedServicesAPI = Service(
    path=LoggedUserBase + '/inherited_services',
    name='LoggedUserInheritedServices')
LoggedUserServicesAPI = Service(
    path=LoggedUserBase + '/services',
    name='LoggedUserServices')
LoggedUserServiceInheritedResourcesAPI = Service(
    path=LoggedUserBase + '/services/{service_name}/inherited_resources',
    name='LoggedUserServiceInheritedResources')
LoggedUserServiceResourcesAPI = Service(
    path=LoggedUserBase + '/services/{service_name}/resources',
    name='LoggedUserServiceResources')
LoggedUserServiceInheritedPermissionsAPI = Service(
    path=LoggedUserBase + '/services/{service_name}/inherited_permissions',
    name='LoggedUserServiceInheritedPermissions')
LoggedUserServicePermissionsAPI = Service(
    path=LoggedUserBase + '/services/{service_name}/permissions',
    name='LoggedUserServicePermissions')
LoggedUserServicePermissionAPI = Service(
    path=LoggedUserBase + '/services/{service_name}/permissions/{permission_name}',
    name='LoggedUserServicePermission')
GroupsAPI = Service(
    path='/groups',
    name='Groups')
GroupAPI = Service(
    path='/groups/{group_name}',
    name='Group')
GroupUsersAPI = Service(
    path='/groups/{group_name}/users',
    name='GroupUsers')
GroupServicesAPI = Service(
    path='/groups/{group_name}/services',
    name='GroupServices')
GroupServicePermissionsAPI = Service(
    path='/groups/{group_name}/services/{service_name}/permissions',
    name='GroupServicePermissions')
GroupServicePermissionAPI = Service(
    path='/groups/{group_name}/services/{service_name}/permissions/{permission_name}',
    name='GroupServicePermission')
GroupServiceResourcesAPI = Service(
    path='/groups/{group_name}/services/{service_name}/resources',
    name='GroupServiceResources')
GroupResourcesAPI = Service(
    path='/groups/{group_name}/resources',
    name='GroupResources')
GroupResourcePermissionsAPI = Service(
    path='/groups/{group_name}/resources/{resource_id}/permissions',
    name='GroupResourcePermissions')
GroupResourcePermissionAPI = Service(
    path='/groups/{group_name}/resources/{resource_id}/permissions/{permission_name}',
    name='GroupResourcePermission')
GroupResourceTypesAPI = Service(
    path='/groups/{group_name}/resources/types/{resource_type}',
    name='GroupResourceTypes')
ResourcesAPI = Service(
    path='/resources',
    name='Resources')
ResourceAPI = Service(
    path='/resources/{resource_id}',
    name='Resource')
ResourcePermissionsAPI = Service(
    path='/resources/{resource_id}/permissions',
    name='ResourcePermissions')
ServicesAPI = Service(
    path='/services',
    name='Services')
ServiceAPI = Service(
    path='/services/{service_name}',
    name='Service')
ServiceTypesAPI = Service(
    path='/services/types/{service_type}',
    name='ServiceTypes')
ServicePermissionsAPI = Service(
    path='/services/{service_name}/permissions',
    name='ServicePermissions')
ServiceResourcesAPI = Service(
    path='/services/{service_name}/resources',
    name='ServiceResources')
ServiceResourceAPI = Service(
    path='/services/{service_name}/resources/{resource_id}',
    name='ServiceResource')
ServiceResourceTypesAPI = Service(
    path='/services/types/{service_type}/resources/types',
    name='ServiceResourceTypes')
ProvidersAPI = Service(
    path='/providers',
    name='Providers')
ProviderSigninAPI = Service(
    path='/providers/{provider_name}/signin',
    name='ProviderSignin')
SigninAPI = Service(
    path='/signin',
    name='signin')
SignoutAPI = Service(
    path='/signout',
    name='signout')
SessionAPI = Service(
    path='/session',
    name='Session')
VersionAPI = Service(
    path='/version',
    name='Version')


class HeaderResponseSchema(colander.MappingSchema):
    content_type = colander.SchemaNode(
        colander.String(),
        default='application/json',
        example='application/json',
        description='Content type of the response body.',
    )
    content_type.name = 'Content-Type'


class HeaderRequestSchema(colander.MappingSchema):
    content_type = colander.SchemaNode(
        colander.String(),
        default='application/json',
        example='application/json',
        missing=colander.drop,
    )
    content_type.name = 'Content-Type'


QueryInheritGroupsPermissions = colander.SchemaNode(
    colander.Boolean(), default=False, missing=colander.drop,
    description='User groups memberships inheritance to resolve service resource permissions.')
QueryCascadeResourcesPermissions = colander.SchemaNode(
    colander.Boolean(), default=False, missing=colander.drop,
    description='Display any service that has at least one sub-resource user permission, '
                'or only services that have user permissions directly set on them.', )


class BaseResponseBodySchema(colander.MappingSchema):
    __code = None
    __desc = None

    def __init__(self, code, description):
        super(BaseResponseBodySchema, self).__init__()
        assert isinstance(code, int)
        assert isinstance(description, six.string_types)
        self.__code = code
        self.__desc = description

        # update the values
        child_nodes = getattr(self, 'children')
        for node in child_nodes:
            if node.name == 'code':
                node.example = self.__code
            if node.name == 'detail':
                node.example = self.__desc

    code = colander.SchemaNode(
        colander.Integer(),
        description="HTTP response code",
        example=__code)
    type = colander.SchemaNode(
        colander.String(),
        description="Response content type",
        example="application/json")
    detail = colander.SchemaNode(
        colander.String(),
        description="Response status message",
        example=__desc)


class ErrorVerifyParamBodySchema(colander.MappingSchema):
    name = colander.SchemaNode(
        colander.String(),
        description="Name of the failing condition parameter.",
        missing=colander.drop)
    value = colander.SchemaNode(
        colander.String(),
        description="Value of the failing condition parameter.")
    compare = colander.SchemaNode(
        colander.String(),
        description="Test comparison value of the failing condition parameter.",
        missing=colander.drop)


class ErrorRequestInfoBodySchema(BaseResponseBodySchema):
    def __init__(self, code, description, **kw):
        super(ErrorRequestInfoBodySchema, self).__init__(code, description, **kw)
        assert code >= 400

    route_name = colander.SchemaNode(
        colander.String(),
        description="Route called that generated the error.",
        example="/users/toto")
    request_url = colander.SchemaNode(
        colander.String(),
        description="Request URL that generated the error.",
        example="http://localhost:2001/magpie/users/toto")
    method = colander.SchemaNode(
        colander.String(),
        description="Request method that generated the error.",
        example="GET")


class InternalServerErrorResponseBodySchema(ErrorRequestInfoBodySchema):
    def __init__(self, **kw):
        kw['code'] = HTTPInternalServerError.code
        super(InternalServerErrorResponseBodySchema, self).__init__(**kw)


class UnauthorizedResponseBodySchema(BaseResponseBodySchema):
    def __init__(self, **kw):
        kw['code'] = HTTPUnauthorized.code
        super(UnauthorizedResponseBodySchema, self).__init__(**kw)

    route_name = colander.SchemaNode(colander.String(), description="Specified route")
    request_url = colander.SchemaNode(colander.String(), description="Specified url")


class UnauthorizedResponseSchema(colander.MappingSchema):
    description = "Unauthorized. Insufficient user privileges or missing authentication headers."
    header = HeaderResponseSchema()
    body = UnauthorizedResponseBodySchema(code=HTTPUnauthorized.code, description=description)


class NotFoundResponseSchema(colander.MappingSchema):
    description = "The route resource could not be found."
    header = HeaderResponseSchema()
    body = ErrorRequestInfoBodySchema(code=HTTPNotFound.code, description=description)


class MethodNotAllowedResponseSchema(colander.MappingSchema):
    description = "The method is not allowed for this resource."
    header = HeaderResponseSchema()
    body = ErrorRequestInfoBodySchema(code=HTTPMethodNotAllowed.code, description=description)


class UnprocessableEntityResponseSchema(colander.MappingSchema):
    description = "Invalid value specified."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPUnprocessableEntity.code, description=description)


class InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Internal Server Error. Unhandled exception occurred."
    header = HeaderResponseSchema()
    body = ErrorRequestInfoBodySchema(code=HTTPInternalServerError.code, description=description)


class ProvidersListSchema(colander.SequenceSchema):
    provider_name = colander.SchemaNode(
        colander.String(),
        description="Available login providers.",
        example="openid",
    )


class ResourceTypesListSchema(colander.SequenceSchema):
    resource_type = colander.SchemaNode(
        colander.String(),
        description="Available resource type under root service.",
        example="file",
    )


class GroupNamesListSchema(colander.SequenceSchema):
    group_name = colander.SchemaNode(
        colander.String(),
        description="List of groups depending on context.",
        example="administrators"
    )


class UserNamesListSchema(colander.SequenceSchema):
    user_name = colander.SchemaNode(
        colander.String(),
        description="Users registered in the db",
        example="bob"
    )


class PermissionListSchema(colander.SequenceSchema):
    permission_name = colander.SchemaNode(
        colander.String(),
        description="Permissions applicable to the service/resource",
        example="read"
    )


class UserBodySchema(colander.MappingSchema):
    user_name = colander.SchemaNode(
        colander.String(),
        description="Name of the user.",
        example="toto")
    email = colander.SchemaNode(
        colander.String(),
        description="Email of the user.",
        example="toto@mail.com")
    group_names = GroupNamesListSchema(
        example=['administrators', 'users']
    )


class GroupBodySchema(colander.MappingSchema):
    group_name = colander.SchemaNode(
        colander.String(),
        description="Name of the group.",
        example="Administrators")
    group_id = colander.SchemaNode(
        colander.Integer(),
        description="ID of the group.",
        example=1)
    description = colander.SchemaNode(
        colander.String(),
        description="Description associated to the group.",
        example="",
        missing=colander.drop)
    member_count = colander.SchemaNode(
        colander.Integer(),
        description="Number of users member of the group.",
        example=2,
        missing=colander.drop)
    user_names = UserNamesListSchema(
        example=['alice', 'bob'],
        missing=colander.drop
    )


class ServiceBodySchema(colander.MappingSchema):
    resource_id = colander.SchemaNode(
        colander.Integer(),
        description="Resource identification number",
    )
    permission_names = PermissionListSchema(
        example=['read', 'write']
    )
    service_name = colander.SchemaNode(
        colander.String(),
        description="Name of the service",
        example="thredds"
    )
    service_type = colander.SchemaNode(
        colander.String(),
        description="Type of the service",
        example="thredds"
    )
    service_sync_type = colander.SchemaNode(
        colander.String(),
        description="Type of resource synchronization implementation.",
        example="thredds"
    )
    public_url = colander.SchemaNode(
        colander.String(),
        description="Proxy URL available for public access with permissions",
        example="http://localhost/twitcher/ows/proxy/thredds"
    )
    service_url = colander.SchemaNode(
        colander.String(),
        description="Private URL of the service (restricted access)",
        example="http://localhost:9999/thredds"
    )


class ResourceBodySchema(colander.MappingSchema):
    resource_id = colander.SchemaNode(
        colander.Integer(),
        description="Resource identification number",
    )
    resource_name = colander.SchemaNode(
        colander.String(),
        description="Name of the resource",
        example="thredds"
    )
    resource_display_name = colander.SchemaNode(
        colander.String(),
        description="Display name of the resource",
        example="Birdhouse Thredds Data Server"
    )
    resource_type = colander.SchemaNode(
        colander.String(),
        description="Type of the resource",
        example="service"
    )
    parent_id = colander.SchemaNode(
        colander.Integer(),
        description="Parent resource identification number",
        default=colander.null,  # if no parent
        missing=colander.drop   # if not returned (basic_info = True)
    )
    root_service_id = colander.SchemaNode(
        colander.Integer(),
        description="Resource tree root service identification number",
        default=colander.null,  # if no parent
        missing=colander.drop   # if not returned (basic_info = True)
    )
    permission_names = PermissionListSchema(example=['read', 'write'])
    permission_names.default = colander.null  # if no parent
    permission_names.missing = colander.drop  # if not returned (basic_info = True)


# TODO: improve by making recursive resources work (?)
class Resource_ChildrenContainerWithoutChildResourceBodySchema(ResourceBodySchema):
    children = colander.MappingSchema(default={})


class Resource_ChildResourceWithoutChildrenBodySchema(colander.MappingSchema):
    id = Resource_ChildrenContainerWithoutChildResourceBodySchema()
    id.name = '{resource_id}'


class Resource_ChildrenContainerWithChildResourceBodySchema(ResourceBodySchema):
    children = Resource_ChildResourceWithoutChildrenBodySchema()


class Resource_ChildResourceWithChildrenContainerBodySchema(colander.MappingSchema):
    id = Resource_ChildrenContainerWithChildResourceBodySchema()
    id.name = '{resource_id}'


class Resource_ServiceWithChildrenResourcesContainerBodySchema(ServiceBodySchema):
    resources = Resource_ChildResourceWithChildrenContainerBodySchema()


class Resource_ServiceType_geoserverapi_SchemaNode(colander.MappingSchema):
    geoserver_api = Resource_ServiceWithChildrenResourcesContainerBodySchema()
    geoserver_api.name = "geoserver-api"


class Resource_ServiceType_ncwms_SchemaNode(colander.MappingSchema):
    ncwms = Resource_ServiceWithChildrenResourcesContainerBodySchema()


class Resource_ServiceType_thredds_SchemaNode(colander.MappingSchema):
    thredds = Resource_ServiceWithChildrenResourcesContainerBodySchema()


class ResourcesSchemaNode(colander.MappingSchema):
    geoserver_api = Resource_ServiceType_geoserverapi_SchemaNode()
    geoserver_api.name = "geoserver-api"
    ncwms = Resource_ServiceType_ncwms_SchemaNode()
    thredds = Resource_ServiceType_thredds_SchemaNode()


class Resources_ResponseBodySchema(BaseResponseBodySchema):
    resources = ResourcesSchemaNode()


class Resource_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Resource query by id refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Resource_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Resource ID not found in db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class Resource_MatchDictCheck_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Resource ID is an invalid literal for `int` type."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class Resource_GET_ResponseBodySchema(BaseResponseBodySchema):
    resource_id = Resource_ChildResourceWithChildrenContainerBodySchema()
    resource_id.name = '{resource_id}'


class Resource_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resource successful."
    header = HeaderResponseSchema()
    body = Resource_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Resource_GET_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed building resource children json formatted tree."
    header = HeaderResponseSchema()
    body = InternalServerErrorResponseBodySchema(code=HTTPInternalServerError.code, description=description)


class Resource_PUT_RequestBodySchema(colander.MappingSchema):
    resource_name = colander.SchemaNode(
        colander.String(),
        description="New name to apply to the resource to update",
    )
    service_push = colander.SchemaNode(
        colander.Boolean(),
        description="Push service resource update to Phoenix",
        missing=False,
    )


class Resource_PUT_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = Resource_PUT_RequestBodySchema()


class Resource_PUT_ResponseBodySchema(BaseResponseBodySchema):
    resource_id = colander.SchemaNode(
        colander.String(),
        description="Updated resource identification number."
    )
    resource_name = colander.SchemaNode(
        colander.String(),
        description="Updated resource name (from object)."
    )
    old_resource_name = colander.SchemaNode(
        colander.String(),
        description="Resource name before update."
    )
    new_resource_name = colander.SchemaNode(
        colander.String(),
        description="Resource name after update."
    )


class Resource_PUT_OkResponseSchema(colander.MappingSchema):
    description = "Update resource successful."
    header = HeaderResponseSchema()
    body = Resource_PUT_ResponseBodySchema(code=HTTPOk.code, description=description)


class Resource_PUT_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to update resource with new name."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Resource_DELETE_RequestBodySchema(colander.MappingSchema):
    service_push = colander.SchemaNode(
        colander.Boolean(),
        description="Push service update to Phoenix if applicable",
        missing=colander.drop,
        default=False,
    )


class Resource_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = Resource_DELETE_RequestBodySchema()


class Resource_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete resource successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Resource_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete resource from db failed."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Resources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resources successful."
    header = HeaderResponseSchema()
    body = Resources_ResponseBodySchema(code=HTTPOk.code, description=description)


class Resources_POST_BodySchema(colander.MappingSchema):
    resource_name = colander.SchemaNode(
        colander.String(),
        description="Name of the resource to create"
    )
    resource_display_name = colander.SchemaNode(
        colander.String(),
        description="Display name of the resource to create, defaults to resource_name.",
        missing=colander.drop
    )
    resource_type = colander.SchemaNode(
        colander.String(),
        description="Type of the resource to create"
    )
    parent_id = colander.SchemaNode(
        colander.String(),
        description="ID of parent resource under which the new resource should be created",
        missing=colander.drop
    )


class Resources_POST_RequestBodySchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = Resources_POST_BodySchema()


class Resource_POST_ResponseBodySchema(BaseResponseBodySchema):
    resource_id = Resource_ChildResourceWithChildrenContainerBodySchema()
    resource_id.name = '{resource_id}'


class Resources_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Create resource successful."
    header = HeaderResponseSchema()
    body = Resource_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class Resources_POST_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid [`resource_name`|`resource_type`|`parent_id`] specified for child resource creation."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Resources_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to insert new resource in service tree using parent id."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Resources_POST_NotFoundResponseSchema(colander.MappingSchema):
    description = "Could not find specified resource parent id."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class Resources_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Resource name already exists at requested tree level for creation."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPConflict.code, description=description)


class ResourcePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionListSchema(example=['read', 'write'])


class ResourcePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resource permissions successful."
    header = HeaderResponseSchema()
    body = ResourcePermissions_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ResourcePermissions_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid resource type to extract permissions."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class ServiceResourcesBodySchema(ServiceBodySchema):
    children = ResourcesSchemaNode()


class ServiceType_access_SchemaNode(colander.MappingSchema):
    frontend = ServiceBodySchema(missing=colander.drop)
    geoserver_web = ServiceBodySchema(missing=colander.drop)
    geoserver_web.name = "geoserver-web"
    magpie = ServiceBodySchema(missing=colander.drop)


class ServiceType_geoserverapi_SchemaNode(colander.MappingSchema):
    geoserver_api = ServiceBodySchema(missing=colander.drop)
    geoserver_api.name = "geoserver-api"


class ServiceType_geoserverwms_SchemaNode(colander.MappingSchema):
    geoserverwms = ServiceBodySchema(missing=colander.drop)


class ServiceType_ncwms_SchemaNode(colander.MappingSchema):
    ncwms = ServiceBodySchema(missing=colander.drop)
    ncwms.name = "ncWMS2"


class ServiceType_projectapi_SchemaNode(colander.MappingSchema):
    project_api = ServiceBodySchema(missing=colander.drop)
    project_api.name = "project-api"


class ServiceType_thredds_SchemaNode(colander.MappingSchema):
    thredds = ServiceBodySchema(missing=colander.drop)


class ServiceType_wfs_SchemaNode(colander.MappingSchema):
    geoserver = ServiceBodySchema(missing=colander.drop)


class ServiceType_wps_SchemaNode(colander.MappingSchema):
    lb_flyingpigeon = ServiceBodySchema(missing=colander.drop)
    flyingpigeon = ServiceBodySchema(missing=colander.drop)
    project = ServiceBodySchema(missing=colander.drop)
    catalog = ServiceBodySchema(missing=colander.drop)
    malleefowl = ServiceBodySchema(missing=colander.drop)
    hummingbird = ServiceBodySchema(missing=colander.drop)


class ServicesSchemaNode(colander.MappingSchema):
    access = ServiceType_access_SchemaNode()
    geoserver_api = ServiceType_geoserverapi_SchemaNode(missing=colander.drop)
    geoserver_api.name = "geoserver-api"
    geoserverwms = ServiceType_geoserverwms_SchemaNode(missing=colander.drop)
    ncwms = ServiceType_ncwms_SchemaNode()
    project_api = ServiceType_projectapi_SchemaNode(missing=colander.drop)
    project_api.name = "project-api"
    thredds = ServiceType_thredds_SchemaNode()
    wfs = ServiceType_wfs_SchemaNode(missing=colander.drop)
    wps = ServiceType_wps_SchemaNode(missing=colander.drop)


class Service_FailureBodyResponseSchema(BaseResponseBodySchema):
    service_name = colander.SchemaNode(
        colander.String(),
        description="Service name extracted from path"
    )


class Service_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Service query by name refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Service_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Service name not found in db."
    header = HeaderResponseSchema()
    body = Service_FailureBodyResponseSchema(code=HTTPNotFound.code, description=description)


class Service_GET_ResponseBodySchema(BaseResponseBodySchema):
    service_name = ServiceBodySchema()
    service_name.name = '{service_name}'


class Service_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service successful."
    header = HeaderResponseSchema()
    body = Service_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Services_GET_ResponseBodySchema(BaseResponseBodySchema):
    services = ServicesSchemaNode()


class Services_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get services successful."
    header = HeaderResponseSchema()
    body = Services_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Services_GET_NotAcceptableResponseBodySchema(BaseResponseBodySchema):
    service_type = colander.SchemaNode(
        colander.String(),
        description="Name of the service type filter employed when applicable",
        missing=colander.drop)


class Services_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` value does not correspond to any of the existing service types."
    header = HeaderResponseSchema()
    body = Services_GET_NotAcceptableResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class Services_POST_BodySchema(colander.MappingSchema):
    service_name = colander.SchemaNode(
        colander.String(),
        description="Name of the service to create",
        example="my_service"
    )
    service_type = colander.SchemaNode(
        colander.String(),
        description="Type of the service to create",
        example="wps"
    )
    service_sync_type = colander.SchemaNode(
        colander.String(),
        description="Type of the service to create",
        example="wps"
    )
    service_url = colander.SchemaNode(
        colander.String(),
        description="Private URL of the service to create",
        example="http://localhost:9000/my_service"
    )


class Services_POST_RequestBodySchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = Services_POST_BodySchema()


class Services_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Service registration to db successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Services_POST_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` value does not correspond to any of the existing service types."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Services_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Service registration forbidden by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Services_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Specified `service_name` value already exists."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPConflict.code, description=description)


class Service_PUT_ResponseBodySchema(colander.MappingSchema):
    service_name = colander.SchemaNode(
        colander.String(),
        description="New service name to apply to service specified in path",
        missing=colander.drop,
        default=colander.null,
        example="my_service_new_name"
    )
    service_url = colander.SchemaNode(
        colander.String(),
        description="New service private URL to apply to service specified in path",
        missing=colander.drop,
        default=colander.null,
        example="http://localhost:9000/new_service_name"
    )
    service_push = colander.SchemaNode(
        colander.Boolean(),
        description="Push service update to Phoenix if applicable",
        missing=colander.drop,
        default=False,
    )


class Service_PUT_RequestBodySchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = Service_PUT_ResponseBodySchema()


class Service_SuccessBodyResponseSchema(BaseResponseBodySchema):
    service = ServiceBodySchema()


class Service_PUT_OkResponseSchema(colander.MappingSchema):
    description = "Update service successful."
    header = HeaderResponseSchema()
    body = Service_SuccessBodyResponseSchema(code=HTTPOk.code, description=description)


class Service_PUT_BadRequestResponseSchema(colander.MappingSchema):
    description = "Logged service values are already equal to update values."
    header = HeaderResponseSchema()
    body = Service_FailureBodyResponseSchema(code=HTTPBadRequest.code, description=description)


class Service_PUT_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Update service failed during value assignment."
    header = HeaderResponseSchema()
    body = Service_FailureBodyResponseSchema(code=HTTPForbidden.code, description=description)


class Service_PUT_ConflictResponseSchema(colander.MappingSchema):
    description = "Specified `service_name` already exists."
    header = HeaderResponseSchema()
    body = Service_FailureBodyResponseSchema(code=HTTPConflict.code, description=description)


# delete service use same method as direct resource delete
Service_DELETE_RequestSchema = Resource_DELETE_RequestSchema


class Service_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete service successful."
    header = HeaderResponseSchema()
    body = ServiceBodySchema(code=HTTPOk.code, description=description)


class Service_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete service from db refused by db."
    header = HeaderResponseSchema()
    body = Service_FailureBodyResponseSchema(code=HTTPForbidden.code, description=description)


class ServicePermissions_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionListSchema(example=['read', 'write'])


class ServicePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service permissions successful."
    header = HeaderResponseSchema()
    body = ServicePermissions_ResponseBodySchema(code=HTTPOk.code, description=description)


class ServicePermissions_GET_NotAcceptableResponseBodySchema(BaseResponseBodySchema):
    service = ServiceBodySchema()


class ServicePermissions_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid service type specified by service."
    header = HeaderResponseSchema()
    body = ServicePermissions_GET_NotAcceptableResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


# create service's resource use same method as direct resource create
ServiceResources_POST_BodySchema = Resources_POST_BodySchema
ServiceResources_POST_RequestBodySchema = Resources_POST_RequestBodySchema
ServiceResources_POST_CreatedResponseSchema = Resources_POST_CreatedResponseSchema
ServiceResources_POST_BadRequestResponseSchema = Resources_POST_BadRequestResponseSchema
ServiceResources_POST_ForbiddenResponseSchema = Resources_POST_ForbiddenResponseSchema
ServiceResources_POST_NotFoundResponseSchema = Resources_POST_NotFoundResponseSchema
ServiceResources_POST_ConflictResponseSchema = Resources_POST_ConflictResponseSchema


# delete service's resource use same method as direct resource delete
ServiceResource_DELETE_RequestSchema = Resource_DELETE_RequestSchema
ServiceResource_DELETE_ForbiddenResponseSchema = Resource_DELETE_ForbiddenResponseSchema
ServiceResource_DELETE_OkResponseSchema = Resource_DELETE_OkResponseSchema


class ServiceResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    service_name = Resource_ServiceWithChildrenResourcesContainerBodySchema()
    service_name.name = '{service_name}'


class ServiceResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service resources successful."
    header = HeaderResponseSchema()
    body = ServiceResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ServiceResourceTypes_GET_ResponseBodySchema(BaseResponseBodySchema):
    resource_types = ResourceTypesListSchema()


class ServiceResourceTypes_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service type resource types successful."
    header = HeaderResponseSchema()
    body = ServiceResourceTypes_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ServiceResourceTypes_GET_FailureBodyResponseSchema(BaseResponseBodySchema):
    service_type = colander.SchemaNode(
        colander.String(),
        description="Service type retrieved from route path."
    )


class ServiceResourceTypes_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to obtain resource types for specified service type."
    header = HeaderResponseSchema()
    body = ServiceResourceTypes_GET_FailureBodyResponseSchema(code=HTTPForbidden.code, description=description)


class ServiceResourceTypes_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` does not exist to obtain its resource types."
    header = HeaderResponseSchema()
    body = ServiceResourceTypes_GET_FailureBodyResponseSchema(code=HTTPNotFound.code, description=description)


class Users_GET_ResponseBodySchema(BaseResponseBodySchema):
    user_names = UserNamesListSchema()


class Users_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get users successful."
    header = HeaderResponseSchema()
    body = Users_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Users_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Get users query refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Users_CheckInfo_ResponseBodySchema(BaseResponseBodySchema):
    param = ErrorVerifyParamBodySchema()


class Users_CheckInfo_Name_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `user_name` value specified."
    header = HeaderResponseSchema()
    body = Users_CheckInfo_ResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_Size_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `user_name` length specified (>{length} characters)." \
        .format(length=MAGPIE_USER_NAME_MAX_LENGTH)
    header = HeaderResponseSchema()
    body = Users_CheckInfo_ResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_Email_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `email` value specified."
    header = HeaderResponseSchema()
    body = Users_CheckInfo_ResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_Password_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `password` value specified."
    header = HeaderResponseSchema()
    body = Users_CheckInfo_ResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_GroupName_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `group_name` value specified."
    header = HeaderResponseSchema()
    body = Users_CheckInfo_ResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_Login_ConflictResponseSchema(colander.MappingSchema):
    description = "Invalid `user_name` already logged in."
    header = HeaderResponseSchema()
    body = Users_CheckInfo_ResponseBodySchema(code=HTTPConflict.code, description=description)


class User_Check_ForbiddenResponseSchema(colander.MappingSchema):
    description = "User check query was refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_Check_ConflictResponseSchema(colander.MappingSchema):
    description = "User name matches an already existing user name."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_POST_RequestBodySchema(colander.MappingSchema):
    user_name = colander.SchemaNode(
        colander.String(),
        description="New name to apply to the user",
        example="john",
    )
    email = colander.SchemaNode(
        colander.String(),
        description="New email to apply to the user",
        example="john@mail.com",
    )
    password = colander.SchemaNode(
        colander.String(),
        description="New password to apply to the user",
        example="itzaseekit",
    )
    group_name = colander.SchemaNode(
        colander.String(),
        description="New password to apply to the user",
        example="users",
    )


class Users_POST_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = User_POST_RequestBodySchema()


class Users_POST_ResponseBodySchema(BaseResponseBodySchema):
    user = UserBodySchema()


class Users_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Add user to db successful."
    header = HeaderResponseSchema()
    body = Users_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class Users_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to add user to db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserNew_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "New user query was refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_PUT_RequestBodySchema(colander.MappingSchema):
    user_name = colander.SchemaNode(
        colander.String(),
        description="New name to apply to the user",
        missing=colander.drop,
        example="john",
    )
    email = colander.SchemaNode(
        colander.String(),
        description="New email to apply to the user",
        missing=colander.drop,
        example="john@mail.com",
    )
    password = colander.SchemaNode(
        colander.String(),
        description="New password to apply to the user",
        missing=colander.drop,
        example="itzaseekit",
    )


class User_PUT_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = User_PUT_RequestBodySchema()


class Users_PUT_OkResponseSchema(colander.MappingSchema):
    description = "Update user successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


# PUT method uses same sub-function as POST method (same responses)
User_PUT_ForbiddenResponseSchema = Users_POST_ForbiddenResponseSchema


class User_PUT_ConflictResponseSchema(colander.MappingSchema):
    description = "New name user already exists."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPConflict.code, description=description)


class User_GET_ResponseBodySchema(BaseResponseBodySchema):
    user = UserBodySchema()


class User_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user successful."
    header = HeaderResponseSchema()
    body = User_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class User_CheckAnonymous_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Anonymous user query refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_CheckAnonymous_NotFoundResponseSchema(colander.MappingSchema):
    description = "Anonymous user not found in db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class User_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "User name query refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "User name not found in db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class User_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = colander.MappingSchema(default={})


class User_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete user successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete user by name refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroup_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Group query was refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroup_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Group for new user doesn't exist."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class UserGroup_Check_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to add user-group to db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroups_GET_ResponseBodySchema(BaseResponseBodySchema):
    group_names = GroupNamesListSchema()


class UserGroups_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user groups successful."
    header = HeaderResponseSchema()
    body = UserGroups_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserGroups_POST_RequestBodySchema(colander.MappingSchema):
    user_name = colander.SchemaNode(
        colander.String(),
        description="Name of the user in the user-group relationship",
        example="toto",
    )
    group_name = colander.SchemaNode(
        colander.String(),
        description="Name of the group in the user-group relationship",
        example="users",
    )


class UserGroups_POST_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = UserGroups_POST_RequestBodySchema()


class UserGroups_POST_ResponseBodySchema(BaseResponseBodySchema):
    user_name = colander.SchemaNode(
        colander.String(),
        description="Name of the user in the user-group relationship",
        example="toto",
    )
    group_name = colander.SchemaNode(
        colander.String(),
        description="Name of the group in the user-group relationship",
        example="users",
    )


class UserGroups_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Create user-group assignation successful."
    header = HeaderResponseSchema()
    body = UserGroups_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class UserGroups_POST_GroupNotFoundResponseSchema(colander.MappingSchema):
    description = "Can't find the group to assign to."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserGroups_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Group query by name refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroups_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "User already belongs to this group."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPConflict.code, description=description)


class UserGroup_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = colander.MappingSchema(default={})


class UserGroup_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete user-group successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class UserGroup_DELETE_NotFoundResponseSchema(colander.MappingSchema):
    description = "Invalid user-group combination for delete."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    resources = ResourcesSchemaNode()


class UserResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user resources successful."
    header = HeaderResponseSchema()
    body = UserResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserResources_GET_NotFoundResponseBodySchema(BaseResponseBodySchema):
    user_name = colander.SchemaNode(colander.String(), description="User name value read from path")
    resource_types = ResourceTypesListSchema(description="Resource types searched for")


class UserResources_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "Failed to populate user resources."
    header = HeaderResponseSchema()
    body = UserResources_GET_NotFoundResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResourcePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionListSchema(example=['read', 'write'])


class UserResourcePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user resource permissions successful."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_GET_ResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResourcePermissions_GET_NotAcceptableParamResponseSchema(colander.MappingSchema):
    name = colander.SchemaNode(colander.String(), description='name of the parameter tested', example='resource_type')
    value = colander.SchemaNode(colander.String(), description='value of the parameter tested')
    compare = colander.SchemaNode(colander.String(), description='comparison value of the parameter tested',
                                  missing=colander.drop)


class UserResourcePermissions_GET_NotAcceptableResponseBodySchema(colander.MappingSchema):
    param = UserResourcePermissions_GET_NotAcceptableParamResponseSchema()


class UserResourcePermissions_GET_NotAcceptableRootServiceResponseSchema(colander.MappingSchema):
    description = "Invalid `resource` specified for resource permission retrieval."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_GET_NotAcceptableResponseBodySchema(
        code=HTTPNotAcceptable.code, description=description)


class UserResourcePermissions_GET_NotAcceptableResourceResponseSchema(colander.MappingSchema):
    description = "Invalid `resource` specified for resource permission retrieval."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_GET_NotAcceptableResponseBodySchema(
        code=HTTPNotAcceptable.code, description=description)


class UserResourcePermissions_GET_NotAcceptableResourceTypeResponseSchema(colander.MappingSchema):
    description = "Invalid `resource_type` for corresponding service resource permission retrieval."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_GET_NotAcceptableResponseBodySchema(
        code=HTTPNotAcceptable.code, description=description)


class UserResourcePermissions_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "Specified user not found to obtain resource permissions."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResourcePermissions_POST_RequestBodySchema(colander.MappingSchema):
    resource_id = colander.SchemaNode(
        colander.Integer(),
        description="resource_id of the created user-resource-permission reference.")
    user_id = colander.SchemaNode(
        colander.Integer(),
        description="user_id of the created user-resource-permission reference.")
    permission_name = colander.SchemaNode(
        colander.String(),
        description="permission_name of the created user-resource-permission reference.")


class UserResourcePermissions_POST_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = UserResourcePermissions_POST_RequestBodySchema()


class UserResourcePermissions_POST_ResponseBodySchema(BaseResponseBodySchema):
    resource_id = colander.SchemaNode(
        colander.Integer(),
        description="resource_id of the created user-resource-permission reference.")
    user_id = colander.SchemaNode(
        colander.Integer(),
        description="user_id of the created user-resource-permission reference.")
    permission_name = colander.SchemaNode(
        colander.String(),
        description="permission_name of the created user-resource-permission reference.")


class UserResourcePermissions_POST_ParamResponseBodySchema(colander.MappingSchema):
    name = colander.SchemaNode(colander.String(), description="Specified parameter.", example='permission_name')
    value = colander.SchemaNode(colander.String(), description="Specified parameter value.")


class UserResourcePermissions_POST_BadResponseBodySchema(BaseResponseBodySchema):
    resource_type = colander.SchemaNode(colander.String(), description="Specified resource_type.")
    resource_name = colander.SchemaNode(colander.String(), description="Specified resource_name.")
    param = UserResourcePermissions_POST_ParamResponseBodySchema()


class UserResourcePermissions_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Create user resource permission successful."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class UserResourcePermissions_POST_BadRequestResponseSchema(colander.MappingSchema):
    description = "Permission not allowed for specified `resource_type`."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_POST_BadResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class UserResourcePermissions_POST_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Failed to create permission using specified `resource_id` and `user_id`."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_POST_BadResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class UserResourcePermissions_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Permission already exist on resource for user, cannot add to db."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_POST_ResponseBodySchema(code=HTTPConflict.code, description=description)


# using same definitions
UserResourcePermissions_DELETE_BadResponseBodySchema = UserResourcePermissions_POST_ResponseBodySchema
UserResourcePermissions_DELETE_BadRequestResponseSchema = UserResourcePermissions_POST_BadRequestResponseSchema


class UserResourcePermission_DELETE_RequestSchema(colander.MappingSchema):
    body = colander.MappingSchema(default={})


class UserResourcePermissions_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete user resource permission successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class UserResourcePermissions_DELETE_NotFoundResponseSchema(colander.MappingSchema):
    description = "Could not find user resource permission to delete from db."
    header = HeaderResponseSchema()
    body = UserResourcePermissions_DELETE_BadResponseBodySchema(code=HTTPOk.code, description=description)


class UserServiceResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    service = ServiceResourcesBodySchema()


class UserServiceResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user service resources successful."
    header = HeaderResponseSchema()
    body = UserServiceResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserServiceResources_GET_QuerySchema(colander.MappingSchema):
    inherit = QueryInheritGroupsPermissions


class UserServiceResources_GET_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    querystring = UserServiceResources_GET_QuerySchema()


class UserServicePermissions_POST_RequestBodySchema(colander.MappingSchema):
    permission_name = colander.SchemaNode(colander.String(), description="Name of the permission to create.")


class UserServicePermissions_POST_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = UserServicePermissions_POST_RequestBodySchema()


class UserServicePermission_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = colander.MappingSchema(default={})


class UserServices_GET_QuerySchema(colander.MappingSchema):
    cascade = QueryCascadeResourcesPermissions
    inherit = QueryInheritGroupsPermissions
    list = colander.SchemaNode(
        colander.Boolean(), default=False, missing=colander.drop,
        description='Return services as a list of dicts. Default is a dict by service type, and by service name.')


class UserServices_GET_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    querystring = UserServices_GET_QuerySchema()


class UserServices_GET_ResponseBodySchema(BaseResponseBodySchema):
    services = ServicesSchemaNode()


class UserServices_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user services successful."
    header = HeaderResponseSchema()
    body = UserServices_GET_ResponseBodySchema


class UserServicePermissions_GET_QuerySchema(colander.MappingSchema):
    inherit = QueryInheritGroupsPermissions


class UserServicePermissions_GET_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    querystring = UserServicePermissions_GET_QuerySchema()


class UserServicePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionListSchema(example=['read', 'write'])


class UserServicePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user service permissions successful."
    header = HeaderResponseSchema()
    body = UserServicePermissions_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserServicePermissions_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "Could not find permissions using specified `service_name` and `user_name`."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class Group_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Group query by name refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Group_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Group name not found in db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class Groups_CheckInfo_NotFoundResponseSchema(colander.MappingSchema):
    description = "User name not found in db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class Groups_CheckInfo_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to obtain groups of user."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Groups_GET_ResponseBodySchema(BaseResponseBodySchema):
    group_names = GroupNamesListSchema()


class Groups_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get groups successful."
    header = HeaderResponseSchema()
    body = Groups_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Groups_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Obtain group names refused by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class Groups_POST_RequestSchema(colander.MappingSchema):
    group_name = colander.SchemaNode(colander.String(), description="Name of the group to create.")


class Groups_POST_ResponseBodySchema(BaseResponseBodySchema):
    group = GroupBodySchema()


class Groups_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Create group successful."
    header = HeaderResponseSchema()
    body = Groups_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class Groups_POST_ForbiddenCreateResponseSchema(colander.MappingSchema):
    description = "Create new group by name refused by db."
    header = HeaderResponseSchema()
    body = Groups_POST_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class Groups_POST_ForbiddenAddResponseSchema(colander.MappingSchema):
    description = "Add new group by name refused by db."
    header = HeaderResponseSchema()
    body = Groups_POST_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class Groups_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Group name matches an already existing group name."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPConflict.code, description=description)


class Group_GET_ResponseBodySchema(BaseResponseBodySchema):
    group = GroupBodySchema()


class Group_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group successful."
    header = HeaderResponseSchema()
    body = Group_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Group_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "Group name was not found."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotFound.code, description=description)


class Group_PUT_RequestSchema(colander.MappingSchema):
    group_name = colander.SchemaNode(colander.String(), description="New name to apply to the group.")


class Group_PUT_OkResponseSchema(colander.MappingSchema):
    description = "Update group successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Group_PUT_Name_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid `group_name` value specified."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class Group_PUT_Size_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid `group_name` length specified (>{length} characters)." \
        .format(length=MAGPIE_USER_NAME_MAX_LENGTH)
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class Group_PUT_Same_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid `group_name` must be different than current name."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class Group_PUT_ConflictResponseSchema(colander.MappingSchema):
    description = "Group name already exists."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPConflict.code, description=description)


class Group_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = colander.MappingSchema(default={})


class Group_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete group successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Group_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete group forbidden by db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class GroupUsers_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group users successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class GroupUsers_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to obtain group user names from db."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupServices_GET_ResponseBodySchema(BaseResponseBodySchema):
    services = ServicesSchemaNode()


class GroupServices_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group services successful."
    header = HeaderResponseSchema()
    body = GroupServices_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServices_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = GroupBodySchema()


class GroupServices_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed to populate group services."
    header = HeaderResponseSchema()
    body = GroupServices_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupServicePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionListSchema(example=['read', 'write'])


class GroupServicePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group service permissions successful."
    header = HeaderResponseSchema()
    body = GroupServicePermissions_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServicePermissions_GET_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = GroupBodySchema()
    service = ServiceBodySchema()


class GroupServicePermissions_GET_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed to extract permissions names from group-service."
    header = HeaderResponseSchema()
    body = GroupServicePermissions_GET_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupServicePermissions_POST_RequestSchema(colander.MappingSchema):
    permission_name = colander.SchemaNode(colander.String(), description="Name of the permission to create.")


GroupResourcePermissions_POST_RequestSchema = GroupServicePermissions_POST_RequestSchema


class GroupResourcePermissions_POST_ResponseBodySchema(BaseResponseBodySchema):
    permission_name = colander.SchemaNode(colander.String(), description="Name of the permission requested.")
    resource = ResourceBodySchema()
    group = GroupBodySchema()


class GroupResourcePermissions_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Create group resource permission successful."
    header = HeaderResponseSchema()
    body = GroupResourcePermissions_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class GroupResourcePermissions_POST_ForbiddenAddResponseSchema(colander.MappingSchema):
    description = "Add group resource permission refused by db."
    header = HeaderResponseSchema()
    body = GroupResourcePermissions_POST_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupResourcePermissions_POST_ForbiddenCreateResponseSchema(colander.MappingSchema):
    description = "Create group resource permission failed."
    header = HeaderResponseSchema()
    body = GroupResourcePermissions_POST_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupResourcePermissions_POST_ForbiddenGetResponseSchema(colander.MappingSchema):
    description = "Get group resource permission failed."
    header = HeaderResponseSchema()
    body = GroupResourcePermissions_POST_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupResourcePermissions_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Group resource permission already exists."
    header = HeaderResponseSchema()
    body = GroupResourcePermissions_POST_ResponseBodySchema(code=HTTPConflict.code, description=description)


class GroupResourcePermission_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = colander.MappingSchema(default={})


class GroupResourcesPermissions_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = colander.SchemaNode(colander.String(), description="Object representation of the group.")
    resource_ids = colander.SchemaNode(colander.String(), description="Object representation of the resource ids.")
    resource_types = colander.SchemaNode(colander.String(), description="Object representation of the resource types.")


class GroupResourcesPermissions_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed to build group resources json tree."
    header = HeaderResponseSchema()
    body = GroupResourcesPermissions_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupResourcePermissions_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = colander.SchemaNode(colander.String(), description="Object representation of the group.")
    resource = colander.SchemaNode(colander.String(), description="Object representation of the resource.")


class GroupResourcePermissions_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed to obtain group resource permissions."
    header = HeaderResponseSchema()
    body = GroupResourcePermissions_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    resources = ResourcesSchemaNode()


class GroupResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group resources successful."
    header = HeaderResponseSchema()
    body = GroupResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupResources_GET_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = colander.SchemaNode(colander.String(), description="Object representation of the group.")


class GroupResources_GET_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed to build group resources json tree."
    header = HeaderResponseSchema()
    body = GroupResources_GET_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupResourcePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permissions_names = PermissionListSchema(example=['read', 'write'])


class GroupResourcePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group resource permissions successful."
    header = HeaderResponseSchema()
    body = GroupResourcePermissions_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServiceResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    service = ServiceResourcesBodySchema()


class GroupServiceResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group service resources successful."
    header = HeaderResponseSchema()
    body = GroupServiceResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServicePermission_DELETE_RequestSchema(colander.MappingSchema):
    permission_name = colander.SchemaNode(colander.String(), description="Name of the permission to delete.")


class GroupServicePermission_DELETE_ResponseBodySchema(BaseResponseBodySchema):
    permission_name = colander.SchemaNode(colander.String(), description="Name of the permission requested.")
    resource = ResourceBodySchema()
    group = GroupBodySchema()


class GroupServicePermission_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete group resource permission successful."
    header = HeaderResponseSchema()
    body = GroupServicePermission_DELETE_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServicePermission_DELETE_ForbiddenGetResponseSchema(colander.MappingSchema):
    description = "Get group resource permission failed."
    header = HeaderResponseSchema()
    body = GroupServicePermission_DELETE_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupServicePermission_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete group resource permission refused by db."
    header = HeaderResponseSchema()
    body = GroupServicePermission_DELETE_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class Signout_GET_OkResponseSchema(colander.MappingSchema):
    description = "Sign out successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServicePermission_DELETE_NotFoundResponseSchema(colander.MappingSchema):
    description = "Permission not found for corresponding group and resource."
    header = HeaderResponseSchema()
    body = GroupServicePermission_DELETE_ResponseBodySchema(code=HTTPNotFound.code, description=description)


class Session_GET_ResponseBodySchema(BaseResponseBodySchema):
    user = UserBodySchema(missing=colander.drop)
    authenticated = colander.SchemaNode(
        colander.Boolean(),
        description="Indicates if any user session is currently authenticated (user logged in).")


class Session_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get session successful."
    header = HeaderResponseSchema()
    body = Session_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Session_GET_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed to get session details."
    header = HeaderResponseSchema()
    body = InternalServerErrorResponseSchema()


class ProvidersBodySchema(colander.MappingSchema):
    internal = ProvidersListSchema()
    external = ProvidersListSchema()


class Providers_GET_ResponseBodySchema(BaseResponseBodySchema):
    providers = ProvidersBodySchema()


class Providers_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get providers successful."
    header = HeaderResponseSchema()
    body = Providers_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ProviderSignin_GET_NotFoundResponseBodySchema(ErrorRequestInfoBodySchema):
    param = ErrorVerifyParamBodySchema()
    provider_name = colander.SchemaNode(colander.String())
    providers = ProvidersListSchema()


class ProviderSignin_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "Invalid `provider_name` not found within available providers."
    header = HeaderResponseSchema()
    body = ProviderSignin_GET_NotFoundResponseBodySchema(code=HTTPNotFound.code, description=description)


class Signin_POST_RequestBodySchema(colander.MappingSchema):
    user_name = colander.SchemaNode(colander.String(), description="User name to use for sign in.")
    password = colander.SchemaNode(colander.String(), description="Password to use for sign in.")
    provider_name = colander.SchemaNode(colander.String(), description="Provider to use for sign in.",
                                        default=MAGPIE_DEFAULT_PROVIDER, missing=colander.drop)


class Signin_POST_RequestSchema(colander.MappingSchema):
    header = HeaderRequestSchema()
    body = Signin_POST_RequestBodySchema()


class Signin_POST_OkResponseSchema(colander.MappingSchema):
    description = "Login successful."
    header = HeaderResponseSchema()
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Signin_POST_BadRequestResponseSchema(colander.MappingSchema):
    description = "Could not retrieve `user_name`."
    header = HeaderResponseSchema()
    body = ErrorRequestInfoBodySchema(code=HTTPBadRequest.code, description=description)


class Signin_POST_UnauthorizedResponseSchema(colander.MappingSchema):
    description = "Login failure."
    header = HeaderResponseSchema()
    body = ErrorRequestInfoBodySchema(code=HTTPUnauthorized.code, description=description)


class Signin_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Could not verify `user_name`."
    header = HeaderResponseSchema()
    body = ErrorRequestInfoBodySchema(code=HTTPForbidden.code, description=description)


class Signin_POST_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Undefined `user_name`."
    header = HeaderResponseSchema()
    body = ErrorRequestInfoBodySchema(code=HTTPNotAcceptable.code, description=description)


class Signin_POST_ConflictResponseBodySchema(ErrorRequestInfoBodySchema):
    provider_name = colander.SchemaNode(colander.String())
    internal_user_name = colander.SchemaNode(colander.String())
    external_user_name = colander.SchemaNode(colander.String())
    external_id = colander.SchemaNode(colander.String())


class Signin_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Add external user identity refused by db because it already exists."
    header = HeaderResponseSchema()
    body = Signin_POST_ConflictResponseBodySchema(code=HTTPConflict.code, description=description)


class Signin_POST_InternalServerErrorBodySchema(InternalServerErrorResponseBodySchema):
    user_name = colander.SchemaNode(colander.String(), description="Specified user retrieved from the request.")
    provider_name = colander.SchemaNode(colander.String(), description="Specified provider retrieved from the request.")


class Signin_POST_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Error occurred while signing in with external provider."
    header = HeaderResponseSchema()
    body = InternalServerErrorResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class Version_GET_ResponseBodySchema(BaseResponseBodySchema):
    version = colander.SchemaNode(
        colander.String(),
        description="Magpie version string",
        example=__meta__.__version__)
    db_version = colander.SchemaNode(
        colander.String(),
        description="Database version string",
        exemple="a395ef9d3fe6")


class Version_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get version successful."
    header = HeaderResponseSchema()
    body = Version_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


# Responses for specific views
Resource_GET_responses = {
    '200': Resource_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Resource_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
    '500': Resource_GET_InternalServerErrorResponseSchema()
}
Resource_PUT_responses = {
    '200': Resource_PUT_OkResponseSchema(),
    '403': Resource_PUT_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
Resources_GET_responses = {
    '200': Resources_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '500': Resource_GET_InternalServerErrorResponseSchema()
}
Resources_POST_responses = {
    '201': Resources_POST_CreatedResponseSchema(),
    '400': Resources_POST_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Resources_POST_ForbiddenResponseSchema(),
    '404': Resources_POST_NotFoundResponseSchema(),
    '409': Resources_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
Resources_DELETE_responses = {
    '200': Resource_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Resource_DELETE_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
ResourcePermissions_GET_responses = {
    '200': ResourcePermissions_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Resource_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': ResourcePermissions_GET_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
ServiceTypes_GET_responses = {
    '200': Services_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '406': Services_GET_NotAcceptableResponseSchema(),
}
Services_GET_responses = {
    '200': Services_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '406': Services_GET_NotAcceptableResponseSchema(),
}
Services_POST_responses = {
    '201': Services_POST_CreatedResponseSchema(),
    '400': Services_POST_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Services_POST_ForbiddenResponseSchema(),
    '409': Services_POST_ConflictResponseSchema(),
}
Service_GET_responses = {
    '200': Service_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
}
Service_PUT_responses = {
    '200': Service_PUT_OkResponseSchema(),
    '400': Service_PUT_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_PUT_ForbiddenResponseSchema(),
    '409': Service_PUT_ConflictResponseSchema(),
}
Service_DELETE_responses = {
    '200': Service_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_DELETE_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
}
ServicePermissions_GET_responses = {
    '200': ServicePermissions_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
    '406': ServicePermissions_GET_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
ServiceResources_GET_responses = {
    '200': ServiceResources_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Service_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
ServiceResources_POST_responses = {
    '201': ServiceResources_POST_CreatedResponseSchema(),
    '400': ServiceResources_POST_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': ServiceResources_POST_ForbiddenResponseSchema(),
    '404': ServiceResources_POST_NotFoundResponseSchema(),
    '409': ServiceResources_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
ServiceResource_GET_responses = {
    '200': ServiceResourceTypes_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': ServiceResourceTypes_GET_ForbiddenResponseSchema(),
    '404': ServiceResourceTypes_GET_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
ServiceResource_DELETE_responses = {
    '200': ServiceResource_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': ServiceResource_DELETE_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
Users_GET_responses = {
    '200': Users_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Users_GET_ForbiddenResponseSchema(),
}
Users_POST_responses = {
    '201': Users_POST_CreatedResponseSchema(),
    '400': Users_CheckInfo_Name_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Users_POST_ForbiddenResponseSchema(),
    '406': UserGroup_GET_NotAcceptableResponseSchema(),
    '409': Users_CheckInfo_Login_ConflictResponseSchema(),
}
User_GET_responses = {
    '200': User_GET_OkResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
User_PUT_responses = {
    '200': Users_PUT_OkResponseSchema(),
    '400': Users_CheckInfo_Name_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': UserGroup_GET_ForbiddenResponseSchema(),
    '406': UserGroup_GET_NotAcceptableResponseSchema(),
    '409': Users_CheckInfo_Login_ConflictResponseSchema(),
}
User_DELETE_responses = {
    '200': User_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserResources_GET_responses = {
    '200': UserResources_GET_OkResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': UserResources_GET_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserGroups_GET_responses = {
    '200': UserGroups_GET_OkResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserGroups_POST_responses = {
    '201': UserGroups_POST_CreatedResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '409': UserGroups_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserGroup_DELETE_responses = {
    '200': UserGroup_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserResourcePermissions_GET_responses = {
    '200': UserResourcePermissions_GET_OkResponseSchema(),
    '403': Resource_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserResourcePermissions_POST_responses = {
    '201': UserResourcePermissions_POST_CreatedResponseSchema(),
    '400': UserResourcePermissions_POST_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '406': UserResourcePermissions_POST_NotAcceptableResponseSchema(),
    '409': UserResourcePermissions_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserResourcePermission_DELETE_responses = {
    '200': UserResourcePermissions_DELETE_OkResponseSchema(),
    '400': UserResourcePermissions_DELETE_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '404': UserResourcePermissions_DELETE_NotFoundResponseSchema(),
    '406': UserResourcePermissions_GET_NotAcceptableResourceResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserServices_GET_responses = {
    '200': UserServices_GET_OkResponseSchema(),
    '403': User_GET_ForbiddenResponseSchema(),
    '404': User_GET_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserServicePermissions_GET_responses = {
    '200': UserServicePermissions_GET_OkResponseSchema(),
    '403': User_GET_ForbiddenResponseSchema(),
    '404': UserServicePermissions_GET_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserServiceResources_GET_responses = {
    '200': UserServiceResources_GET_OkResponseSchema(),
    '403': User_GET_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
UserServicePermissions_POST_responses = UserResourcePermissions_POST_responses
UserServicePermission_DELETE_responses = UserResourcePermission_DELETE_responses
LoggedUser_GET_responses = {
    '200': User_GET_OkResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUser_PUT_responses = {
    '200': Users_PUT_OkResponseSchema(),
    '400': Users_CheckInfo_Name_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': UserGroup_GET_ForbiddenResponseSchema(),
    '406': UserGroup_GET_NotAcceptableResponseSchema(),
    '409': Users_CheckInfo_Login_ConflictResponseSchema(),
}
LoggedUser_DELETE_responses = {
    '200': User_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserResources_GET_responses = {
    '200': UserResources_GET_OkResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': UserResources_GET_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserGroups_GET_responses = {
    '200': UserGroups_GET_OkResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserGroups_POST_responses = {
    '201': UserGroups_POST_CreatedResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '409': UserGroups_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserGroup_DELETE_responses = {
    '200': UserGroup_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': User_CheckAnonymous_ForbiddenResponseSchema(),
    '404': User_CheckAnonymous_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserResourcePermissions_GET_responses = {
    '200': UserResourcePermissions_GET_OkResponseSchema(),
    '403': Resource_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Resource_MatchDictCheck_NotFoundResponseSchema(),
    '406': Resource_MatchDictCheck_NotAcceptableResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserResourcePermissions_POST_responses = {
    '201': UserResourcePermissions_POST_CreatedResponseSchema(),
    '400': UserResourcePermissions_POST_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '406': UserResourcePermissions_POST_NotAcceptableResponseSchema(),
    '409': UserResourcePermissions_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserResourcePermission_DELETE_responses = {
    '200': UserResourcePermissions_DELETE_OkResponseSchema(),
    '400': UserResourcePermissions_DELETE_BadRequestResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '404': UserResourcePermissions_DELETE_NotFoundResponseSchema(),
    '406': UserResourcePermissions_GET_NotAcceptableResourceResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserServices_GET_responses = {
    '200': UserServices_GET_OkResponseSchema(),
    '403': User_GET_ForbiddenResponseSchema(),
    '404': User_GET_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserServicePermissions_GET_responses = {
    '200': UserServicePermissions_GET_OkResponseSchema(),
    '403': User_GET_ForbiddenResponseSchema(),
    '404': UserServicePermissions_GET_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserServiceResources_GET_responses = {
    '200': UserServiceResources_GET_OkResponseSchema(),
    '403': User_GET_ForbiddenResponseSchema(),
    '404': Service_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
LoggedUserServicePermissions_POST_responses = LoggedUserResourcePermissions_POST_responses
LoggedUserServicePermission_DELETE_responses = LoggedUserResourcePermission_DELETE_responses
Groups_GET_responses = {
    '200': Groups_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Groups_GET_ForbiddenResponseSchema(),
}
Groups_POST_responses = {
    '201': Groups_POST_CreatedResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Groups_POST_ForbiddenCreateResponseSchema(),
    '409': Groups_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
Group_GET_responses = {
    '200': Group_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Group_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
Group_PUT_responses = {
    '200': Group_PUT_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Group_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '406': Group_PUT_Name_NotAcceptableResponseSchema(),
    '409': Group_PUT_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
Group_DELETE_responses = {
    '200': Group_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Group_DELETE_ForbiddenResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
GroupUsers_GET_responses = {
    '200': GroupUsers_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': GroupUsers_GET_ForbiddenResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
GroupServices_GET_responses = {
    '200': GroupServices_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
    '500': GroupServices_InternalServerErrorResponseSchema(),
}
GroupServicePermissions_GET_responses = {
    '200': GroupServicePermissions_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Group_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
    '500': GroupServicePermissions_GET_InternalServerErrorResponseSchema(),
}
GroupServiceResources_GET_responses = {
    '200': GroupServiceResources_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Group_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
GroupResourcePermissions_POST_responses = {
    '201': GroupResourcePermissions_POST_CreatedResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': GroupResourcePermissions_POST_ForbiddenGetResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '409': GroupResourcePermissions_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
GroupServicePermissions_POST_responses = GroupResourcePermissions_POST_responses
GroupServicePermission_DELETE_responses = {
    '200': GroupServicePermission_DELETE_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': GroupServicePermission_DELETE_ForbiddenResponseSchema(),
    '404': GroupServicePermission_DELETE_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
GroupResources_GET_responses = {
    '200': GroupResources_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Group_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
    '500': GroupResources_GET_InternalServerErrorResponseSchema(),
}
GroupResourcePermissions_GET_responses = {
    '200': GroupResourcePermissions_GET_OkResponseSchema(),
    '401': UnauthorizedResponseSchema(),
    '403': Group_MatchDictCheck_ForbiddenResponseSchema(),
    '404': Group_MatchDictCheck_NotFoundResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
}
GroupResourcePermission_DELETE_responses = GroupServicePermission_DELETE_responses
Providers_GET_responses = {
    '200': Providers_GET_OkResponseSchema(),
}
ProviderSignin_GET_responses = {
    '404': ProviderSignin_GET_NotFoundResponseSchema(),
    '500': InternalServerErrorResponseSchema()
}
Signin_POST_responses = {
    '200': Signin_POST_OkResponseSchema(),
    '400': Signin_POST_BadRequestResponseSchema(),
    '401': Signin_POST_UnauthorizedResponseSchema(),
    '403': Signin_POST_ForbiddenResponseSchema(),
    '404': ProviderSignin_GET_NotFoundResponseSchema(),
    '406': Signin_POST_NotAcceptableResponseSchema(),
    '409': Signin_POST_ConflictResponseSchema(),
    '422': UnprocessableEntityResponseSchema(),
    '500': Signin_POST_InternalServerErrorResponseSchema(),
}
Signout_GET_responses = {
    '200': Signout_GET_OkResponseSchema(),
}
Session_GET_responses = {
    '200': Session_GET_OkResponseSchema(),
    '500': Session_GET_InternalServerErrorResponseSchema()
}
Version_GET_responses = {
    '200': Version_GET_OkResponseSchema()
}


# use Cornice Services and Schemas to return swagger specifications
def api_schema(request):
    """
    Return JSON Swagger specifications of Magpie REST API.
    """
    generator = CorniceSwagger(get_services())
    # function docstrings are used to create the route's summary in Swagger-UI
    generator.summary_docstrings = True
    generator.default_security = get_security
    swagger_base_spec = {
        'host': request.host,
        'schemes': [request.scheme]
    }
    swagger_base_spec.update(SecurityDefinitionsAPI)
    generator.swagger = swagger_base_spec
    json_api_spec = generator.generate(title=TitleAPI, version=__meta__.__version__, info=InfoAPI, base_path='/magpie')
    return json_api_spec
