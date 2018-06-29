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
GroupAPI = Service(
    path='/groups/{group_name}',
    name='Group')
ResourcesAPI = Service(
    path='/resources',
    name='Resources')
ResourceAPI = Service(
    path='/resources/{resource_id}',
    name='Resource')
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


class PermissionSchema(colander.SequenceSchema):
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
    permission_names = PermissionSchema()
    service_name = colander.SchemaNode(
        colander.String(),
        description="Name of the service",
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
    service_type = colander.SchemaNode(
        colander.String(),
        description="Type of the service",
        example="thredds"
    )


class ServiceType_thredds_SchemaNode(colander.MappingSchema):
    thredds = ServiceBodySchema()


class ServiceType_ncwms_SchemaNode(colander.MappingSchema):
    ncwms = ServiceBodySchema()


class ServiceType_geoserverapi_SchemaNode(colander.MappingSchema):
    geoserver_api = ServiceBodySchema()
    geoserver_api.name = "geoserver-api"


class ServicesSchemaNode(colander.MappingSchema):
    geoserver_api = ServiceType_geoserverapi_SchemaNode()
    geoserver_api.name = "geoserver-api"
    ncwms = ServiceType_ncwms_SchemaNode()
    thredds = ServiceType_thredds_SchemaNode()


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


class Service_MatchDictCheck_ForbiddenResponseBodySchema(colander.MappingSchema):
    description = "Service query by name refused by db."
    body = BaseBodySchema(code=403)


class Service_MatchDictCheck_NotFoundResponseBodySchema(colander.MappingSchema):
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
    json_api_spec = generator('Magpie REST API', __version__)
    return json_api_spec


#def openapi_spec_generate_json(request):
#    api_json = requests.post()
