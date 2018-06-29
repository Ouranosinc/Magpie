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


# Service Routes
SwaggerAPI = Service(
    path='__api__',
    name='Magpie REST API',
    description="Magpie REST API documentation")
UserAPI = Service(
    path='/users/{user_name}',
    name='User')
UsersAPI = Service(
    path='/users/{user_name}',
    name='Users')
UserGroupAPI = Service(
    path='/users/{user_name}/groups',
    name='UserGroup')
UserInheritedResourcesAPI = Service(
    path='/users/{user_name}/inherited_resources',
    name='UserInheritedResources')
UserResourcesAPI = Service(
    path='/users/{user_name}/resources',
    name='UserResources')
UserResourcesPermissionsAPI = Service(
    path='/users/{user_name}/resources',
    name='UserResourcesPermissions')
UserInheritedServicesAPI = Service(
    path='/users/{user_name}/inherited_services',
    name='UserInheritedServices')
UserServicesAPI = Service(
    path='/users/{user_name}/services',
    name='UserServices')
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
ServicesTypesAPI = Service(
    path='/services/types/{service_type}',
    name='ServicesTypes')
ServiceAPI = Service(
    path='/services/{service_name}',
    name='Service')
SessionAPI = Service(
    path='/session',
    name='Session')
VersionAPI = Service(
    path='/version',
    name='Version')

CodeSchemaNode = colander.SchemaNode(colander.Integer(), description="HTTP response code", example=200)
TypeSchemaNode = colander.SchemaNode(colander.String(), description="Response content type", example="application/json")
DetailSchemaNode = colander.SchemaNode(colander.String(),description="Response status message")


class BaseSchema(colander.MappingSchema):
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


class ServiceBodySchemaNode(colander.MappingSchema):
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
    thredds = ServiceBodySchemaNode()


class ServiceType_ncwms_SchemaNode(colander.MappingSchema):
    ncwms = ServiceBodySchemaNode()


class ServiceType_geoserverapi_SchemaNode(colander.MappingSchema):
    geoserver_api = ServiceBodySchemaNode()
    geoserver_api.name = "geoserver-api"


class ServicesSchemaNode(colander.MappingSchema):
    geoserver_api = ServiceType_geoserverapi_SchemaNode()
    geoserver_api.name = "geoserver-api"
    ncwms = ServiceType_ncwms_SchemaNode()
    thredds = ServiceType_thredds_SchemaNode()


class Services_GET_ResponseBodySchema(colander.MappingSchema):
    services = ServicesSchemaNode()
    code = CodeSchemaNode
    type = TypeSchemaNode
    detail = DetailSchemaNode
    detail.example = "Get services successful."


class Services_GET_OkResponseSchema(colander.MappingSchema):
    description = "Get services successful."
    body = Services_GET_ResponseBodySchema()


class Services_GET_NotAcceptableResponseSchema(colander.MappingSchema):
    description = "Invalid `service_type` value does not correspond to any of the existing service types."
    body = Services_GET_ResponseBodySchema()


class Services_POST_RequestBodySchema(colander.MappingSchema):
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


#  NOT REQUIRED field
#field = colader.SchemaNode(colander.String(), missing=colader.drop)


# return JSON Swagger specifications of Magpie REST API on route '/magpie/__api__'
# using all Cornice Services and Schemas
@SwaggerAPI.get(tags=[APITag])
def api_spec(request=None):
    generator = CorniceSwagger(get_services())
    json_api_spec = generator('Magpie REST API', __version__)
    return json_api_spec


#def openapi_spec_generate_json(request):
#    api_json = requests.post()
