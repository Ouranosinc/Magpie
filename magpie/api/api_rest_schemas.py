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
ResourceAPI = Service(
    path='/resources/{resource_id}',
    name='Resource')
ServiceAPI = Service(
    path='/services/{service_name}',
    name='Service')
VersionAPI = Service(
    path='/version',
    name='Version')
#NotFoundAPI = Service(name='NotFound', path='/', description="Route not found")


class BaseSchema(colander.MappingSchema):
    code = colander.SchemaNode(colander.Integer(), description="HTTP response code")
    type = colander.SchemaNode(colander.String(), description="Response content type")
    detail = colander.SchemaNode(colander.String(), description="Response status message")


#class NotFoundResponseSchema(colander.MappingSchema):
#    code = colander.SchemaNode(colander.Integer(), description="HTTP response code")
#    type = colander.SchemaNode(colander.String(), description="Response content type")
#    detail = colander.SchemaNode(colander.String(), description="Response status message")
#    route_name = colander.SchemaNode(colander.String(), description="Specified route")
#    request_url = colander.SchemaNode(colander.String(), description="Specified url")


class Version_GET_Schema(colander.MappingSchema):
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
    body = Version_GET_Schema()


#  NOT REQUIRED field
#field = colader.SchemaNode(colander.String(), missing=colader.drop)

# Responses Schemas
###HTTP200_User_ResponseSchema


#class OkResponseSchema(colander.MappingSchema):
#    body = BaseSchema()


# return JSON Swagger specifications of Magpie REST API on route '/magpie/__api__'
# using all Cornice Services and Schemas
@SwaggerAPI.get(tags=[APITag])
def api_spec(request):
    generator = CorniceSwagger(get_services())
    json_api_spec = generator('Magpie REST API', __version__)
    return json_api_spec


#def openapi_spec_generate_json(request):
#    api_json = requests.post()
