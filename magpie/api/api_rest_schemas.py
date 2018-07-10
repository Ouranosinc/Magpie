from definitions.cornice_definitions import *
from definitions.pyramid_definitions import *
from db import get_database_revision
import __meta__
import requests


class CorniceSwaggerPredicate(object):
    """Predicate to add simple information to Cornice Swagger."""

    def __init__(self, schema, config):
        self.schema = schema

    def phash(self):
        return str(self.schema)

    def __call__(self, context, request):
        return self.schema


TitleAPI = "Magpie REST API"
InfoAPI = {
    "description": __meta__.__description__,
    "contact": {"name": __meta__.__maintainer__, "email": __meta__.__email__, "url": __meta__.__url__}
}


# Tags
APITag = 'API'
LoginTag = 'Login'
UsersTag = 'User'
CurrentUserTag = 'Current User'
GroupsTag = 'Group'
ResourcesTag = 'Resource'
ServicesTag = 'Service'


# Security
SecurityDefinitionAPI = {'securityDefinitions': {'cookieAuth': {'type': 'apiKey', 'in': 'cookie', 'name': 'auth_tkt'}}}
SecurityAdministratorAPI = [{'cookieAuth': []}]
SecurityEveryoneAPI = []


def get_security(service, method):
    definitions = service.definitions
    args = {}
    for definition in definitions:
        met, view, args = definition
        if met == method:
            break
    return SecurityAdministratorAPI if 'security' not in args else args['security']


# Service Routes
def service_api_route_info(service_api):
    return {'name': service_api.name, 'pattern': service_api.path}


SwaggerAPI = Service(
    path='__api__',
    name='Magpie REST API',
    description="Magpie REST API documentation")
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
CurrentUserAPI = Service(
    path='/users/current',
    name='CurrentUser')
CurrentUserGroupsAPI = Service(
    path='/users/current/groups',
    name='CurrentUserGroups')
CurrentUserGroupAPI = Service(
    path='/users/current/groups/{group_name}',
    name='CurrentUserGroup')
CurrentUserInheritedResourcesAPI = Service(
    path='/users/current/inherited_resources',
    name='CurrentUserInheritedResources')
CurrentUserResourcesAPI = Service(
    path='/users/current/resources',
    name='CurrentUserResources')
CurrentUserResourceInheritedPermissionsAPI = Service(
    path='/users/current/resources/{resource_id}/inherited_permissions',
    name='CurrentUserResourceInheritedPermissions')
CurrentUserResourcePermissionAPI = Service(
    path='/users/current/resources/{resource_id}/permissions/{permission_name}',
    name='CurrentUserResourcePermission')
CurrentUserResourcePermissionsAPI = Service(
    path='/users/current/resources/{resource_id}/permissions',
    name='CurrentUserResourcePermissions')
CurrentUserResourceTypesAPI = Service(
    path='/users/current/resources/types/{resource_type}',
    name='CurrentUserResourceTypes')
CurrentUserInheritedServicesAPI = Service(
    path='/users/current/inherited_services',
    name='CurrentUserInheritedServices')
CurrentUserServicesAPI = Service(
    path='/users/current/services',
    name='CurrentUserServices')
CurrentUserServiceInheritedResourcesAPI = Service(
    path='/users/current/services/{service_name}/inherited_resources',
    name='CurrentUserServiceInheritedResources')
CurrentUserServiceResourcesAPI = Service(
    path='/users/current/services/{service_name}/resources',
    name='CurrentUserServiceResources')
CurrentUserServiceInheritedPermissionsAPI = Service(
    path='/users/current/services/{service_name}/inherited_permissions',
    name='CurrentUserServiceInheritedPermissions')
CurrentUserServicePermissionsAPI = Service(
    path='/users/current/services/{service_name}/permissions',
    name='CurrentUserServicePermissions')
CurrentUserServicePermissionAPI = Service(
    path='/users/current/services/{service_name}/permissions/{permission_name}',
    name='CurrentUserServicePermission')
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
SessionAPI = Service(
    path='/session',
    name='Session')
VersionAPI = Service(
    path='/version',
    name='Version')


CodeSchemaNode = colander.SchemaNode(colander.Integer(), description="HTTP response code", example=HTTPOk.code)
TypeSchemaNode = colander.SchemaNode(colander.String(), description="Response content type", example="application/json")
DetailSchemaNode = colander.SchemaNode(colander.String(), description="Response status message")


class HeaderSchema(colander.MappingSchema):
    content_type = colander.SchemaNode(
        colander.String(),
        example='application/json'
    )
    content_type.name = 'Content-Type'


class BaseBodySchema(colander.MappingSchema):
    def __init__(self, code=None):
        super(BaseBodySchema, self).__init__()
        self.code = CodeSchemaNode
        self.code.example = code
        self.type = TypeSchemaNode
        self.detail = DetailSchemaNode


class ErrorVerifyParamBodySchema(colander.MappingSchema):
    name = colander.SchemaNode(
        colander.String(),
        description="Name of the failing condition parameter",
        missing=colander.drop)
    value = colander.SchemaNode(
        colander.String(),
        description="Value of the failing condition parameter")
    compare = colander.SchemaNode(
        colander.String(),
        description="Test comparison value of the failing condition parameter",
        missing=colander.drop)


class UnauthorizedResponseSchema(colander.MappingSchema):
    description = "Unauthorized. Insufficient user privileges or missing authentication headers."
    code = CodeSchemaNode
    code.example = 401
    type = TypeSchemaNode
    detail = DetailSchemaNode
    route_name = colander.SchemaNode(colander.String(), description="Specified route")
    request_url = colander.SchemaNode(colander.String(), description="Specified url")


class NotFoundResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    code.example = HTTPNotFound.code
    type = TypeSchemaNode
    detail = DetailSchemaNode
    route_name = colander.SchemaNode(colander.String(), description="Specified route")
    request_url = colander.SchemaNode(colander.String(), description="Specified url")


class UnprocessableEntityResponseSchema(colander.MappingSchema):
    description = "Invalid value specified."
    body = BaseBodySchema(HTTPUnprocessableEntity.code)


class InternalServerErrorBodySchema(colander.MappingSchema):
    code = colander.SchemaNode(
        colander.Integer(),
        description="HTTP response code",
        example=500)
    type = colander.SchemaNode(
        colander.String(),
        description="Response content type",
        example="application/json")
    detail = colander.SchemaNode(
        colander.String(),
        description="Response status message",
        example="Internal Server Error. Unhandled exception occurred.")
    route_name = colander.SchemaNode(
        colander.String(),
        description="Route called that generated the error",
        example="/users/toto")
    request_url = colander.SchemaNode(
        colander.String(),
        description="Request URL that generated the error",
        example="http://localhost:HTTPOk.code1/magpie/users/toto")


class InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Internal Server Error. Unhandled exception occurred."
    body = InternalServerErrorBodySchema()


class ResourceTypesListSchema(colander.SequenceSchema):
    item = colander.SchemaNode(
        colander.String(),
        description="Available resource type under root service.",
        example=["file", "dictionary"],
    )


class GroupNamesListSchema(colander.SequenceSchema):
    item = colander.SchemaNode(
        colander.String(),
        description="Groups the logged in user is member of",
        example=["anonymous"]
    )


class UserNamesListSchema(colander.SequenceSchema):
    item = colander.SchemaNode(
        colander.String(),
        description="Users registered in the db",
        example=["anonymous", "admin", "toto"]
    )


class PermissionListSchema(colander.SequenceSchema):
    item = colander.SchemaNode(
        colander.String(),
        description="Permissions applicable to the service/resource",
        example=["read", "write"]
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
    group_names = GroupNamesListSchema()


class ServiceBodySchema(colander.MappingSchema):
    resource_id = colander.SchemaNode(
        colander.Integer(),
        description="Resource identification number",
    )
    permission_names = PermissionListSchema()
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
    permission_names = PermissionListSchema()
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


class Resources_BodyResponseSchema(colander.MappingSchema):
    resources = ResourcesSchemaNode()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Resource_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Resource query by id refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class Resource_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Resource ID not found in db."
    body = BaseBodySchema(code=HTTPNotFound.code)


class Resource_MatchDictCheck_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Resource ID is an invalid literal for `int` type."
    body = BaseBodySchema(code=HTTPNotAcceptable.code)


class Resource_GET_BodyResponseSchema(colander.MappingSchema):
    resource_id = Resource_ChildResourceWithChildrenContainerBodySchema()
    resource_id.name = '{resource_id}'
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Resource_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resource successful."
    body = Resource_GET_BodyResponseSchema()


class Resource_GET_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed building resource children json formatted tree."
    body = InternalServerErrorBodySchema()


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
    header = HeaderSchema()
    body = Resource_PUT_RequestBodySchema()


class Resource_PUT_BodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
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
    body = Resource_PUT_BodyResponseSchema()


class Resource_PUT_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to update resource with new name."
    body = BaseBodySchema(code=HTTPForbidden.code)


class Resource_DELETE_RequestBodySchema(colander.MappingSchema):
    service_push = colander.SchemaNode(
        colander.Boolean(),
        description="Push service update to Phoenix if applicable",
        missing=colander.drop,
        default=False,
    )


class Resource_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderSchema()
    body = Resource_DELETE_RequestBodySchema()


class Resource_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete resource successful."
    body = BaseBodySchema(code=HTTPOk.code)


class Resource_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete resource from db failed."
    body = BaseBodySchema(code=HTTPForbidden.code)


class Resources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resources successful."
    body = Resources_BodyResponseSchema()


class Resources_POST_BodySchema(colander.MappingSchema):
    resource_name = colander.SchemaNode(
        colander.String(),
        description="Name of the resource to create"
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
    header = HeaderSchema()
    body = Resources_POST_BodySchema()


class Resource_POST_BodyResponseSchema(colander.MappingSchema):
    resource_id = Resource_ChildResourceWithChildrenContainerBodySchema()
    resource_id.name = '{resource_id}'
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Resources_POST_OkResponseSchema(colander.MappingSchema):
    description = "Create resource successful."
    body = Resource_POST_BodyResponseSchema()


class Resources_POST_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid [`resource_name`|`resource_type`|`parent_id`] specified for child resource creation."
    body = BaseBodySchema(code=HTTPBadRequest.code)


class Resources_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to insert new resource in service tree using parent id."
    body = BaseBodySchema(code=HTTPForbidden.code)


class Resources_POST_NotFoundResponseSchema(colander.MappingSchema):
    description = "Could not find specified resource parent id."
    body = BaseBodySchema(code=HTTPNotFound.code)


class Resources_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Resource name already exists at requested tree level for creation."
    body = BaseBodySchema(code=HTTPConflict.code)


class ResourcePermissions_GET_BodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    permission_names = PermissionListSchema()


class ResourcePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resource permissions successful."
    body = ResourcePermissions_GET_BodyResponseSchema()


class ResourcePermissions_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid resource type to extract permissions."
    body = BaseBodySchema(code=HTTPNotAcceptable.code)


class ServiceResourcesBodySchema(ServiceBodySchema):
    children = ResourcesSchemaNode()


class ServiceType_access_SchemaNode(colander.MappingSchema):
    frontend = ServiceBodySchema()
    geoserver_web = ServiceBodySchema()
    geoserver_web.name = "geoserver-web"
    magpie = ServiceBodySchema()


class ServiceType_geoserverapi_SchemaNode(colander.MappingSchema):
    geoserver_api = ServiceBodySchema()
    geoserver_api.name = "geoserver-api"


class ServiceType_geoserverwms_SchemaNode(colander.MappingSchema):
    geoserverwms = ServiceBodySchema()


class ServiceType_ncwms_SchemaNode(colander.MappingSchema):
    ncwms = ServiceBodySchema()
    ncwms.name = "ncWMS2"


class ServiceType_projectapi_SchemaNode(colander.MappingSchema):
    project_api = ServiceBodySchema()
    project_api.name = "project-api"


class ServiceType_thredds_SchemaNode(colander.MappingSchema):
    thredds = ServiceBodySchema()


class ServiceType_wfs_SchemaNode(colander.MappingSchema):
    geoserver = ServiceBodySchema()


class ServiceType_wps_SchemaNode(colander.MappingSchema):
    lb_flyingpigeon = ServiceBodySchema()
    flyingpigeon = ServiceBodySchema()
    project = ServiceBodySchema()
    catalog = ServiceBodySchema()
    malleefowl = ServiceBodySchema()
    hummingbird = ServiceBodySchema()


class ServicesSchemaNode(colander.MappingSchema):
    access = ServiceType_access_SchemaNode()
    geoserver_api = ServiceType_geoserverapi_SchemaNode()
    geoserver_api.name = "geoserver-api"
    geoserverwms = ServiceType_geoserverwms_SchemaNode()
    ncwms = ServiceType_ncwms_SchemaNode()
    project_api = ServiceType_projectapi_SchemaNode()
    project_api.name = "project-api"
    thredds = ServiceType_thredds_SchemaNode()
    wfs = ServiceType_wfs_SchemaNode()
    wps = ServiceType_wps_SchemaNode()


class Service_FailureBodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    service_name = colander.SchemaNode(
        colander.String(),
        description="Service name extracted from path"
    )


class Service_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Service query by name refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class Service_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Service name not found in db."
    body = Service_FailureBodyResponseSchema(code=HTTPNotFound.code)


class Service_GET_BodyResponseSchema(colander.MappingSchema):
    service_name = ServiceBodySchema()
    service_name.name = '{service_name}'
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Service_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service successful."
    body = Service_GET_BodyResponseSchema()


class Services_GET_BodyResponseSchema(colander.MappingSchema):
    services = ServicesSchemaNode()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    detail.example = "Get services successful."


class Services_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get services successful."
    body = Services_GET_BodyResponseSchema()


class Services_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` value does not correspond to any of the existing service types."
    body = Services_GET_BodyResponseSchema()


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
    service_url = colander.SchemaNode(
        colander.String(),
        description="Private URL of the service to create",
        example="http://localhost:9000/my_service"
    )


class Services_POST_RequestBodySchema(colander.MappingSchema):
    header = HeaderSchema()
    body = Services_POST_BodySchema()


class Services_POST_BodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Services_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Service registration to db successful."
    body = Services_POST_BodyResponseSchema()


class Services_POST_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` value does not correspond to any of the existing service types."
    body = Services_POST_BodyResponseSchema(code=HTTPBadRequest.code)


class Services_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Service registration forbidden by db."
    body = Services_POST_BodyResponseSchema(code=HTTPForbidden.code)


class Services_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Specified `service_name` value already exists."
    body = Services_POST_BodyResponseSchema(code=HTTPConflict.code)


class Service_PUT_BodySchema(colander.MappingSchema):
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
    header = HeaderSchema()
    body = Service_PUT_BodySchema()


class Service_SuccessBodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    service = ServiceBodySchema()


class Service_PUT_OkResponseSchema(colander.MappingSchema):
    description = "Update service successful."
    body = Service_SuccessBodyResponseSchema(code=HTTPOk.code)


class Service_PUT_BadRequestResponseSchema(colander.MappingSchema):
    description = "Current service values are already equal to update values."
    body = Service_FailureBodyResponseSchema(code=HTTPBadRequest.code)


class Service_PUT_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Update service failed during value assignment."
    body = Service_FailureBodyResponseSchema(code=HTTPForbidden.code)


class Service_PUT_ConflictResponseSchema(colander.MappingSchema):
    description = "Specified `service_name` already exists."
    body = Service_FailureBodyResponseSchema(code=HTTPConflict.code)


# delete service use same method as direct resource delete
Service_DELETE_RequestSchema = Resource_DELETE_RequestSchema


class Service_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete service successful."
    body = ServiceBodySchema(code=HTTPOk.code)


class Service_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete service from db refused by db."
    body = Service_FailureBodyResponseSchema(code=HTTPForbidden.code)


class ServicePermissions_BodyResponseSchema(colander.MappingSchema):
    permission_names = PermissionListSchema()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class ServicePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service permissions successful."
    body = ServicePermissions_BodyResponseSchema()


class ServicePermissions_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid service type specified by service."
    body = ServicePermissions_BodyResponseSchema()


# create service's resource use same method as direct resource create
ServiceResources_POST_BodySchema = Resources_POST_BodySchema
ServiceResources_POST_RequestBodySchema = Resources_POST_RequestBodySchema
ServiceResources_POST_OkResponseSchema = Resources_POST_OkResponseSchema
ServiceResources_POST_BadRequestResponseSchema = Resources_POST_BadRequestResponseSchema
ServiceResources_POST_ForbiddenResponseSchema = Resources_POST_ForbiddenResponseSchema
ServiceResources_POST_NotFoundResponseSchema = Resources_POST_NotFoundResponseSchema
ServiceResources_POST_ConflictResponseSchema = Resources_POST_ConflictResponseSchema


# delete service's resource use same method as direct resource delete
ServiceResource_DELETE_RequestSchema = Resource_DELETE_RequestSchema
ServiceResource_DELETE_ForbiddenResponseSchema = Resource_DELETE_ForbiddenResponseSchema
ServiceResource_DELETE_OkResponseSchema = Resource_DELETE_OkResponseSchema


class ServiceResources_GET_BodyResponseSchema(colander.MappingSchema):
    service_name = Resource_ServiceWithChildrenResourcesContainerBodySchema()
    service_name.name = '{service_name}'
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class ServiceResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service resources successful."
    body = ServiceResources_GET_BodyResponseSchema()


class ServiceResourceTypes_GET_BodyResponseSchema(colander.MappingSchema):
    resource_types = ResourceTypesListSchema()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class ServiceResourceTypes_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service type resource types successful."
    body = ServiceResourceTypes_GET_BodyResponseSchema()


class ServiceResourceTypes_GET_FailureBodyResponseSchema(colander.MappingSchema):
    service_type = colander.SchemaNode(
        colander.String(),
        description="Service type retrieved from route path."
    )
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class ServiceResourceTypes_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to obtain resource types for specified service type."
    body = ServiceResourceTypes_GET_FailureBodyResponseSchema(code=HTTPForbidden.code)


class ServiceResourceTypes_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` does not exist to obtain its resource types."
    body = ServiceResourceTypes_GET_FailureBodyResponseSchema(code=HTTPNotFound.code)


class Users_GET_BodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    user_names = UserNamesListSchema()


class Users_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get users successful."
    body = Users_GET_BodyResponseSchema()


class Users_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Get users query refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class Users_CheckInfo_BodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    param = ErrorVerifyParamBodySchema()


class Users_CheckInfo_Name_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `user_name` value specified."
    body = Users_CheckInfo_BodyResponseSchema()


class Users_CheckInfo_Email_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `email` value specified."
    body = Users_CheckInfo_BodyResponseSchema()


class Users_CheckInfo_Password_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `password` value specified."
    body = Users_CheckInfo_BodyResponseSchema()


class Users_CheckInfo_GroupName_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `group_name` value specified."
    body = Users_CheckInfo_BodyResponseSchema()


class Users_CheckInfo_Login_ConflictResponseSchema(colander.MappingSchema):
    description = "Invalid `user_name` already logged in."
    body = Users_CheckInfo_BodyResponseSchema()


class User_Check_ForbiddenResponseSchema(colander.MappingSchema):
    description = "User check query was refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class User_Check_ConflictResponseSchema(colander.MappingSchema):
    description = "User name matches an already existing user name."
    body = BaseBodySchema(code=HTTPForbidden.code)


class User_POST_BodyRequestSchema(colander.MappingSchema):
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
    header = HeaderSchema()
    body = User_POST_BodyRequestSchema()


class Users_POST_BodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    user = UserBodySchema()


class Users_POST_OkResponseSchema(colander.MappingSchema):
    description = "Add user to db successful."
    body = Users_POST_BodyResponseSchema()


class Users_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to add user to db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class UserNew_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "New user query was refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class User_PUT_BodyRequestSchema(colander.MappingSchema):
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
    header = HeaderSchema()
    body = User_PUT_BodyRequestSchema()


class Users_PUT_OkResponseSchema(colander.MappingSchema):
    description = "Update user successful."
    body = BaseBodySchema(code=HTTPOk.code)


# PUT method uses same sub-function as POST method (same responses)
User_PUT_ForbiddenResponseSchema = Users_POST_ForbiddenResponseSchema


class User_PUT_ConflictResponseSchema(colander.MappingSchema):
    description = "New name user already exists."
    body = BaseBodySchema(code=HTTPConflict.code)


class User_GET_BodyResponseSchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    user = UserBodySchema()


class User_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user successful."
    body = User_GET_BodyResponseSchema()


class User_CheckAnonymous_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Anonymous user query refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class User_CheckAnonymous_NotFoundResponseSchema(colander.MappingSchema):
    description = "Anonymous user not found in db."
    body = BaseBodySchema(code=HTTPNotFound.code)


class User_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "User name query refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class User_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "User name not found in db."
    body = BaseBodySchema(code=HTTPNotFound.code)


class User_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderSchema()
    body = {}


class User_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete user successful."
    body = BaseBodySchema(code=HTTPForbidden.code)


class User_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete user by name refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class UserGroup_GET_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Group query was refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class UserGroup_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Group for new user doesn't exist."
    body = BaseBodySchema(code=HTTPNotAcceptable.code)


class UserGroup_Check_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to add user-group to db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class UserGroups_POST_BodyRequestSchema(colander.MappingSchema):
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
    header = HeaderSchema()
    body = UserGroups_POST_BodyRequestSchema()


class UserGroups_POST_BodyResponseSchema(BaseBodySchema):
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


class UserGroups_POST_OkResponseSchema(colander.MappingSchema):
    description = "Create user-group assignation successful."
    body = UserGroups_POST_BodyResponseSchema(code=HTTPOk.code)


class UserGroups_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "User already belongs to this group."
    body = BaseBodySchema(code=HTTPConflict.code)


class UserGroup_DELETE_RequestSchema(colander.MappingSchema):
    header = HeaderSchema()
    body = {}


class UserGroup_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete user-group successful."
    body = BaseBodySchema(code=HTTPOk.code)


class UserGroup_DELETE_NotFoundResponseSchema(colander.MappingSchema):
    description = "Invalid user-group combination for delete."
    body = BaseBodySchema(code=HTTPNotFound.code)


class UserResources_GET_BodyResponseSchema(BaseBodySchema):
    resources = ResourcesSchemaNode


class UserResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user resources successful."
    body = UserResources_GET_BodyResponseSchema()


class UserResources_GET_NotFoundBodyResponseSchema(BaseBodySchema):
    user_name = colander.SchemaNode(colander.String(), description="User name value read from path")
    resource_types = ResourceTypesListSchema(description="Resource types searched for")


class UserResources_GET_NotFoundResponseSchema(colander.MappingSchema):
    description = "Failed to populate user resources."
    body = UserResources_GET_NotFoundBodyResponseSchema(code=HTTPNotFound.code)


class UserResourcePermissions_GET_BodyResponseSchema(BaseBodySchema):
    permission_names = PermissionListSchema()


class UserResourcePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get user resource permissions successful."
    body = UserResourcePermissions_GET_BodyResponseSchema(code=HTTPNotFound.code)


class Group_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Group query by name refused by db."
    body = BaseBodySchema(code=HTTPForbidden.code)


class Group_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Group name not found in db."
    body = BaseBodySchema(code=HTTPNotFound.code)


class GroupServiceResources_GET_BodyResponseSchema(BaseBodySchema):
    service = ServiceResourcesBodySchema()


class GroupServiceResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group service resources successful."
    body = GroupServiceResources_GET_BodyResponseSchema()


class Session_GET_BodyResponseSchema(BaseBodySchema):
    user_name = colander.SchemaNode(
        colander.String(),
        description="Currently logged in user name (anonymous if none)",
        example="anonymous")
    user_email = colander.SchemaNode(
        colander.String(),
        description="Currently logged in user email",
        example="anonymous@mail.com")
    group_names = GroupNamesListSchema()


class Session_GET_OkResponseSchema(colander.MappingSchema):
    body = Session_GET_BodyResponseSchema()


class Version_GET_BodyResponseSchema(colander.MappingSchema):
    code = colander.SchemaNode(
        colander.Integer(),
        description="HTTP response code",
        example=HTTPOk.code)
    type = colander.SchemaNode(
        colander.String(),
        description="Response content type",
        example="application/json")
    detail = colander.SchemaNode(
        colander.String(),
        description="Response status message",
        example="Get version successful.")
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
    body = Version_GET_BodyResponseSchema()


@SwaggerAPI.get(tags=[APITag])
def api_spec(request=None, use_docstring_summary=False):
    """
    Return JSON Swagger specifications of Magpie REST API on route '/magpie/__api__' using Cornice Services and Schemas.
    """
    generator = CorniceSwagger(get_services())
    # function docstrings are used to create the route's summary in Swagger-UI
    generator.summary_docstrings = use_docstring_summary
    generator.default_security = get_security
    generator.swagger = SecurityDefinitionAPI
    json_api_spec = generator.generate(title=TitleAPI, version=__meta__.__version__, info=InfoAPI)
    return json_api_spec
