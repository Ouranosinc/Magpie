from definitions.cornice_definitions import *
from definitions.pyramid_definitions import view_config
from db import get_database_revision
from __meta__ import __version__
import requests


class CorniceSwaggerPredicate(object):
    """Predicate to add simple information to Cornice Swagger."""

    def __init__(self, schema, config):
        self.schema = schema

    def phash(self):
        return str(self.schema)

    def __call__(self, context, request):
        return self.schema


# Tags
APITag = 'API'
LoginTag = 'Login'
UserTag = 'User'
GroupTag = 'Group'
ResourceTag = 'Resource'
ServiceTag = 'Service'


def service_api_route_info(service_api):
    return {'name': service_api.name, 'pattern': service_api.path}


# Service Routes
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
UserResourcesTypesAPI = Service(
    path='/users/{user_name}/resources/types/{resource_type}',
    name='UserResourcesTypes')
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
GroupResourcesTypesAPI = Service(
    path='/groups/{group_name}/resources/types/{resource_type}',
    name='GroupResourcesTypes')
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
ServicesTypesAPI = Service(
    path='/services/types/{service_type}',
    name='ServicesTypes')
ServicePermissionsAPI = Service(
    path='/services/{service_name}/permissions',
    name='ServicePermissions')
ServiceResourcesAPI = Service(
    path='/services/{service_name}/resources',
    name='ServiceResources')
ServiceResourceAPI = Service(
    path='/services/{service_name}/resources/{resource_id}',
    name='ServiceResource')
ServiceResourcesTypesAPI = Service(
    path='/services/types/{service_type}/resources/types',
    name='ServiceResourcesTypes')
SessionAPI = Service(
    path='/session',
    name='Session')
VersionAPI = Service(
    path='/version',
    name='Version')


CodeSchemaNode = colander.SchemaNode(colander.Integer(), description="HTTP response code", example=200)
TypeSchemaNode = colander.SchemaNode(colander.String(), description="Response content type", example="application/json")
DetailSchemaNode = colander.SchemaNode(colander.String(), description="Response status message")


class HeaderSchema(colander.MappingSchema):
    content_type = colander.SchemaNode(
        colander.String(),
        example='application/json'
    )
    content_type.name = 'Content-Type'


class BaseBodySchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


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
    code.example = 404
    type = TypeSchemaNode
    detail = DetailSchemaNode
    route_name = colander.SchemaNode(colander.String(), description="Specified route")
    request_url = colander.SchemaNode(colander.String(), description="Specified url")


class UnprocessableEntityBodySchema(colander.MappingSchema):
    code = CodeSchemaNode
    code.example = 422
    type = TypeSchemaNode
    detail = DetailSchemaNode


class UnprocessableEntityResponseSchema(colander.MappingSchema):
    description = "Invalid value specified."
    body = UnprocessableEntityBodySchema()


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
        example="http://localhost:2001/magpie/users/toto")


class InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Internal Server Error. Unhandled exception occurred."
    body = InternalServerErrorBodySchema()


class GroupNamesListSchema(colander.SequenceSchema):
    item = colander.SchemaNode(
        colander.String(),
        description="Groups the logged in user is member of",
        example=["anonymous"]
    )


class PermissionListSchema(colander.SequenceSchema):
    item = colander.SchemaNode(
        colander.String(),
        description="Permissions applicable to the service/resource",
        example=["read", "write"]
    )


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
        missing=colander.drop  # if not returned (basic_info = True)
    )
    root_service_id = colander.SchemaNode(
        colander.Integer(),
        description="Resource tree root service identification number",
        default=colander.null,  # if no parent
        missing=colander.drop  # if not returned (basic_info = True)
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


class Resources_ResponseBodySchema(colander.MappingSchema):
    resources = ResourcesSchemaNode()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Resource_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Resource query by id refused by db."
    body = BaseBodySchema(code=403)


class Resource_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Resource ID not found in db."
    body = BaseBodySchema(code=404)


class Resource_MatchDictCheck_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Resource ID is an invalid literal for `int` type."
    body = BaseBodySchema(code=406)


class Resource_GET_ResponseBodySchema(colander.MappingSchema):
    resource_id = Resource_ChildResourceWithChildrenContainerBodySchema()
    resource_id.name = '{resource_id}'
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Resource_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resource successful."
    body = Resource_GET_ResponseBodySchema()


class Resource_GET_InternalServerErrorResponseSchema(colander.MappingSchema):
    description = "Failed building resource children json formatted tree."
    body = InternalServerErrorBodySchema()


class Resource_DELETE_RequestBodySchema(colander.MappingSchema):
    header = HeaderSchema()


class Resource_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete resource successful."
    body = BaseBodySchema(code=200)


class Resource_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete resource from db failed."
    body = BaseBodySchema(code=403)


class Resources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resources successful."
    body = Resources_ResponseBodySchema()


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


class Resource_POST_ResponseBodySchema(colander.MappingSchema):
    resource_id = Resource_ChildResourceWithChildrenContainerBodySchema()
    resource_id.name = '{resource_id}'
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Resources_POST_OkResponseSchema(colander.MappingSchema):
    description = "Create resource successful."
    body = Resource_POST_ResponseBodySchema()


class Resources_POST_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid [`resource_name`|`resource_type`|`parent_id`] specified for child resource creation."
    body = BaseBodySchema(code=400)


class Resources_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Failed to insert new resource in service tree using parent id."
    body = BaseBodySchema(code=403)


class Resources_POST_NotFoundResponseSchema(colander.MappingSchema):
    description = "Could not find specified resource parent id."
    body = BaseBodySchema(code=404)


class Resources_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Resource name already exists at requested tree level for creation."
    body = BaseBodySchema(code=409)


class ResourcePermissions_GET_ResponseBodySchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    permission_names = PermissionListSchema()


class ResourcePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get resource permissions successful."
    body = ResourcePermissions_GET_ResponseBodySchema()


class ResourcePermissions_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid resource type to extract permissions."
    body = BaseBodySchema(code=406)


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


class Service_FailureResponseBodySchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    service_name = colander.SchemaNode(
        colander.String(),
        description="Service name extracted from path"
    )


class Services_GET_ResponseBodySchema(colander.MappingSchema):
    services = ServicesSchemaNode()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    detail.example = "Get services successful."


class Services_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get services successful."
    body = Services_GET_ResponseBodySchema()


class Service_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Service query by name refused by db."
    body = BaseBodySchema(code=403)


class Service_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Service name not found in db."
    body = Service_FailureResponseBodySchema(code=404)


class Service_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service successful."
    body = Service_FailureResponseBodySchema()


class Services_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` value does not correspond to any of the existing service types."
    body = Services_GET_ResponseBodySchema()


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


class Services_POST_ResponseBodySchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class Services_POST_CreatedResponseSchema(colander.MappingSchema):
    description = "Service registration to db successful."
    body = Services_POST_ResponseBodySchema()


class Services_POST_BadRequestResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` value does not correspond to any of the existing service types."
    body = Services_POST_ResponseBodySchema(code=400)


class Services_POST_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Service registration forbidden by db."
    body = Services_POST_ResponseBodySchema(code=403)


class Services_POST_ConflictResponseSchema(colander.MappingSchema):
    description = "Specified `service_name` value already exists."
    body = Services_POST_ResponseBodySchema(code=409)


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


class Service_SuccessResponseBodySchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    service = ServiceBodySchema()


class Service_PUT_OkResponseSchema(colander.MappingSchema):
    description = "Update service successful."
    body = Service_SuccessResponseBodySchema(code=200)


class Service_PUT_BadRequestResponseSchema(colander.MappingSchema):
    description = "Current service values are already equal to update values."
    body = Service_FailureResponseBodySchema(code=400)


class Service_PUT_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Update service failed during value assignment."
    body = Service_FailureResponseBodySchema(code=403)


class Service_PUT_ConflictResponseSchema(colander.MappingSchema):
    description = "Specified `service_name` already exists."
    body = Service_FailureResponseBodySchema(code=409)


class Service_DELETE_BodySchema(colander.MappingSchema):
    service_push = colander.SchemaNode(
        colander.Boolean(),
        description="Push service update to Phoenix if applicable",
        missing=colander.drop,
        default=False
    )


class Service_DELETE_RequestBodySchema(colander.MappingSchema):
    header = HeaderSchema()
    body = Service_DELETE_BodySchema(missing=colander.drop)


class Service_DELETE_OkResponseSchema(colander.MappingSchema):
    description = "Delete service successful."
    body = ServiceBodySchema(code=200)


class Service_DELETE_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Delete service from db refused by db."
    body = Service_FailureResponseBodySchema(code=403)


class ServicePermissions_ResponseBodySchema(colander.MappingSchema):
    permission_names = PermissionListSchema()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class ServicePermissions_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service permissions successful."
    body = ServicePermissions_ResponseBodySchema()


class ServicePermissions_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid service type specified by service."
    body = ServicePermissions_ResponseBodySchema()


# create service's resource use same method as direct resource create
ServiceResources_POST_BodySchema = Resources_POST_BodySchema
ServiceResources_POST_RequestBodySchema = Resources_POST_RequestBodySchema
ServiceResources_POST_OkResponseSchema = Resources_POST_OkResponseSchema
ServiceResources_POST_BadRequestResponseSchema = Resources_POST_BadRequestResponseSchema
ServiceResources_POST_ForbiddenResponseSchema = Resources_POST_ForbiddenResponseSchema
ServiceResources_POST_NotFoundResponseSchema = Resources_POST_NotFoundResponseSchema
ServiceResources_POST_ConflictResponseSchema = Resources_POST_ConflictResponseSchema


# delete service's resource use same method as direct resource delete
ServiceResource_DELETE_RequestBodySchema = Resource_DELETE_RequestBodySchema
ServiceResource_DELETE_ForbiddenResponseSchema = Resource_DELETE_ForbiddenResponseSchema
ServiceResource_DELETE_OkResponseSchema = Resource_DELETE_OkResponseSchema


class ServiceResources_GET_ResponseBodySchema(colander.MappingSchema):
    service_name = ServiceBodySchema()
    service_name.name = '{service_name}'
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class ServiceResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get service resources successful."
    body = ServiceResources_GET_ResponseBodySchema()


class Group_MatchDictCheck_ForbiddenResponseSchema(colander.MappingSchema):
    description = "Group query by name refused by db."
    body = BaseBodySchema(code=403)


class Group_MatchDictCheck_NotFoundResponseSchema(colander.MappingSchema):
    description = "Group name not found in db."
    body = BaseBodySchema(code=404)


class GroupServiceResources_GET_ResponseBodySchema(colander.MappingSchema):
    service = ServiceResourcesBodySchema()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode


class GroupServiceResources_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get group service resources successful."
    body = GroupServiceResources_GET_ResponseBodySchema()


class Session_GET_ResponseBodySchema(colander.MappingSchema):
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    detail.example = "Get session successful."
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
    body = Session_GET_ResponseBodySchema()


class Version_GET_ResponseBodySchema(colander.MappingSchema):
    code = colander.SchemaNode(
        colander.Integer(),
        description="HTTP response code",
        example=200)
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
        example=__version__)
    db_version = colander.SchemaNode(
        colander.String(),
        description="Database version string",
        exemple="a395ef9d3fe6")


class Version_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get version successful."
    body = Version_GET_ResponseBodySchema()


# return JSON Swagger specifications of Magpie REST API on route '/magpie/__api__'
# using all Cornice Services and Schemas
@SwaggerAPI.get(tags=[APITag])
def api_spec(request=None):
    generator = CorniceSwagger(get_services())
    generator.summary_docstrings = True  # function docstrings are used to create the route's summary in Swagger-UI
    json_api_spec = generator('Magpie REST API', __version__)
    return json_api_spec


#def openapi_spec_generate_json(request):
#    api_json = requests.post()
