import uuid
from typing import TYPE_CHECKING

import colander
import six
from cornice import Service
from cornice.service import get_services
from cornice_swagger.swagger import CorniceSwagger
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPFound,
    HTTPGone,
    HTTPInternalServerError,
    HTTPMethodNotAllowed,
    HTTPNotAcceptable,
    HTTPNotFound,
    HTTPOk,
    HTTPUnauthorized,
    HTTPUnprocessableEntity
)
from pyramid.security import NO_PERMISSION_REQUIRED

from magpie import __meta__
from magpie.constants import get_constant
from magpie.permissions import Access, Permission, PermissionType, Scope
from magpie.security import get_provider_names
from magpie.utils import (
    CONTENT_TYPE_HTML,
    CONTENT_TYPE_JSON,
    KNOWN_CONTENT_TYPES,
    SUPPORTED_ACCEPT_TYPES,
    SUPPORTED_FORMAT_TYPES
)

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Dict, List, Union

    from magpie.typedefs import JSON, Str

# ignore naming style of tags
# pylint: disable=C0103,invalid-name

TitleAPI = "Magpie REST API"
InfoAPI = {
    "description": __meta__.__description__,
    "contact": {"name": __meta__.__maintainer__, "email": __meta__.__email__, "url": __meta__.__url__}
}


# Security
SecurityCookieAuthAPI = {"cookieAuth": {"type": "apiKey", "in": "cookie", "name": get_constant("MAGPIE_COOKIE_NAME")}}
SecurityDefinitionsAPI = {"securityDefinitions": SecurityCookieAuthAPI}
SecurityAuthenticatedAPI = [{"cookieAuth": []}]
SecurityAdministratorAPI = [{"cookieAuth": []}]
SecurityEveryoneAPI = [{}]


def get_security(service, method):
    definitions = service.definitions
    args = {}
    for definition in definitions:
        met, _, args = definition
        if met == method:
            break
    # automatically retrieve permission if specified within the view definition
    permission = args.get("permission")
    if permission == NO_PERMISSION_REQUIRED:
        return SecurityEveryoneAPI
    if permission == get_constant("MAGPIE_ADMIN_PERMISSION"):
        return SecurityAdministratorAPI
    # return default admin permission otherwise unless specified form cornice decorator
    return SecurityAdministratorAPI if "security" not in args else args["security"]


# Path definitions (from services and parameters)

def service_api_route_info(service_api, **kwargs):
    kwargs.update({
        "name": service_api.name,
        "pattern": service_api.path,
    })
    kwargs.setdefault("traverse", getattr(service_api, "traverse", None))
    kwargs.setdefault("factory", getattr(service_api, "factory", None))
    return kwargs


# Service Routes
_LOGGED_USER_VALUE = get_constant("MAGPIE_LOGGED_USER")
LoggedUserBase = "/users/{}".format(_LOGGED_USER_VALUE)

# Values for the 'status' field in the Users database
UserOKStatus = 1
UserWebhookErrorStatus = 0

SwaggerGenerator = Service(
    path="/json",
    name="swagger_schema_json")
SwaggerAPI = Service(
    path="/api",
    name="swagger_schema_ui",
    description="{} documentation".format(TitleAPI))
UsersAPI = Service(
    path="/users",
    name="Users")
UserAPI = Service(
    path="/users/{user_name}",
    name="User")
UserGroupsAPI = Service(
    path="/users/{user_name}/groups",
    name="UserGroups")
UserGroupAPI = Service(
    path="/users/{user_name}/groups/{group_name}",
    name="UserGroup")
UserResourcesAPI = Service(
    path="/users/{user_name}/resources",
    name="UserResources")
UserResourcePermissionsAPI = Service(
    path="/users/{user_name}/resources/{resource_id}/permissions",
    name="UserResourcePermissions")
UserResourcePermissionAPI = Service(
    path="/users/{user_name}/resources/{resource_id}/permissions/{permission_name}",
    name="UserResourcePermission")
UserResourceTypesAPI = Service(
    path="/users/{user_name}/resources/types/{resource_type}",
    name="UserResourceTypes")
UserServicesAPI = Service(
    path="/users/{user_name}/services",
    name="UserServices")
UserServiceAPI = Service(
    path="/users/{user_name}/services/{service_name}",
    name="UserService")
UserServiceResourcesAPI = Service(
    path="/users/{user_name}/services/{service_name}/resources",
    name="UserServiceResources")
UserServicePermissionsAPI = Service(
    path="/users/{user_name}/services/{service_name}/permissions",
    name="UserServicePermissions")
UserServicePermissionAPI = Service(
    path="/users/{user_name}/services/{service_name}/permissions/{permission_name}",
    name="UserServicePermission")
LoggedUserAPI = Service(
    path=LoggedUserBase,
    name="LoggedUser")
LoggedUserGroupsAPI = Service(
    path=LoggedUserBase + "/groups",
    name="LoggedUserGroups")
LoggedUserGroupAPI = Service(
    path=LoggedUserBase + "/groups/{group_name}",
    name="LoggedUserGroup")
LoggedUserResourcesAPI = Service(
    path=LoggedUserBase + "/resources",
    name="LoggedUserResources")
LoggedUserResourcePermissionAPI = Service(
    path=LoggedUserBase + "/resources/{resource_id}/permissions/{permission_name}",
    name="LoggedUserResourcePermission")
LoggedUserResourcePermissionsAPI = Service(
    path=LoggedUserBase + "/resources/{resource_id}/permissions",
    name="LoggedUserResourcePermissions")
LoggedUserResourceTypesAPI = Service(
    path=LoggedUserBase + "/resources/types/{resource_type}",
    name="LoggedUserResourceTypes")
LoggedUserServicesAPI = Service(
    path=LoggedUserBase + "/services",
    name="LoggedUserServices")
LoggedUserServiceResourcesAPI = Service(
    path=LoggedUserBase + "/services/{service_name}/resources",
    name="LoggedUserServiceResources")
LoggedUserServicePermissionsAPI = Service(
    path=LoggedUserBase + "/services/{service_name}/permissions",
    name="LoggedUserServicePermissions")
LoggedUserServicePermissionAPI = Service(
    path=LoggedUserBase + "/services/{service_name}/permissions/{permission_name}",
    name="LoggedUserServicePermission")
GroupsAPI = Service(
    path="/groups",
    name="Groups")
GroupAPI = Service(
    path="/groups/{group_name}",
    name="Group")
GroupUsersAPI = Service(
    path="/groups/{group_name}/users",
    name="GroupUsers")
GroupServicesAPI = Service(
    path="/groups/{group_name}/services",
    name="GroupServices")
GroupServicePermissionsAPI = Service(
    path="/groups/{group_name}/services/{service_name}/permissions",
    name="GroupServicePermissions")
GroupServicePermissionAPI = Service(
    path="/groups/{group_name}/services/{service_name}/permissions/{permission_name}",
    name="GroupServicePermission")
GroupServiceResourcesAPI = Service(
    path="/groups/{group_name}/services/{service_name}/resources",
    name="GroupServiceResources")
GroupResourcesAPI = Service(
    path="/groups/{group_name}/resources",
    name="GroupResources")
GroupResourcePermissionsAPI = Service(
    path="/groups/{group_name}/resources/{resource_id}/permissions",
    name="GroupResourcePermissions")
GroupResourcePermissionAPI = Service(
    path="/groups/{group_name}/resources/{resource_id}/permissions/{permission_name}",
    name="GroupResourcePermission")
GroupResourceTypesAPI = Service(
    path="/groups/{group_name}/resources/types/{resource_type}",
    name="GroupResourceTypes")
RegisterGroupsAPI = Service(
    path="/register/groups",
    name="RegisterGroups")
RegisterGroupAPI = Service(
    path="/register/groups/{group_name}",
    name="RegisterGroup")
ResourcesAPI = Service(
    path="/resources",
    name="Resources")
ResourceAPI = Service(
    path="/resources/{resource_id}",
    name="Resource")
ResourcePermissionsAPI = Service(
    path="/resources/{resource_id}/permissions",
    name="ResourcePermissions")
ServicesAPI = Service(
    path="/services",
    name="Services")
ServiceAPI = Service(
    path="/services/{service_name}",
    name="Service")
ServiceTypesAPI = Service(
    path="/services/types",
    name="ServiceTypes")
ServiceTypeAPI = Service(
    path="/services/types/{service_type}",
    name="ServiceType")
ServicePermissionsAPI = Service(
    path="/services/{service_name}/permissions",
    name="ServicePermissions")
ServiceResourcesAPI = Service(
    path="/services/{service_name}/resources",
    name="ServiceResources")
ServiceResourceAPI = Service(
    path="/services/{service_name}/resources/{resource_id}",
    name="ServiceResource")
ServiceTypeResourcesAPI = Service(
    path="/services/types/{service_type}/resources",
    name="ServiceTypeResources")
ServiceTypeResourceTypesAPI = Service(
    path="/services/types/{service_type}/resources/types",
    name="ServiceTypeResourceTypes")
ProvidersAPI = Service(
    path="/providers",
    name="Providers")
ProviderSigninAPI = Service(
    path="/providers/{provider_name}/signin",
    name="ProviderSignin")
SigninAPI = Service(
    path="/signin",
    name="signin")
SignoutAPI = Service(
    path="/signout",
    name="signout")
SessionAPI = Service(
    path="/session",
    name="Session")
VersionAPI = Service(
    path="/version",
    name="Version")
HomepageAPI = Service(
    path="/",
    name="homepage")
TemporaryUrlAPI = Service(
    path="/tmp/{token}",  # nosec: B108
    name="temporary_url")


# Path parameters
GroupNameParameter = colander.SchemaNode(
    colander.String(),
    description="Registered user group.",
    example="users",)
UserNameParameter = colander.SchemaNode(
    colander.String(),
    description="Registered local user.",
    example="toto",)
ProviderNameParameter = colander.SchemaNode(
    colander.String(),
    description="External identity provider.",
    example="DKRZ",
    validator=colander.OneOf(get_provider_names()))
PermissionNameParameter = colander.SchemaNode(
    colander.String(),
    description="Permissions applicable to the service/resource.",
    example=Permission.READ.value,)
ResourceIdParameter = colander.SchemaNode(
    colander.String(),
    description="Registered resource ID.",
    example="123")
ResourceTypeParameter = colander.SchemaNode(
    colander.String(),
    description="Known resource type.",
    example="process")
ServiceNameParameter = colander.SchemaNode(
    colander.String(),
    description="Registered service name.",
    example="my-wps")
ServiceTypeParameter = colander.SchemaNode(
    colander.String(),
    description="Known service type.",
    example="wps")
TokenParameter = colander.SchemaNode(
    colander.String(),
    description="Temporary URL token.",
    example=str(uuid.uuid4()))


class ServiceType_RequestPathSchema(colander.MappingSchema):
    service_type = ServiceTypeParameter


class Service_RequestPathSchema(colander.MappingSchema):
    service_name = ServiceNameParameter


class Resource_RequestPathSchema(colander.MappingSchema):
    resource_id = ResourceIdParameter


class ServiceResource_RequestPathSchema(colander.MappingSchema):
    service_name = ServiceNameParameter
    resource_id = ResourceIdParameter


class Permission_RequestPathSchema(colander.MappingSchema):
    permission_name = PermissionNameParameter


class Group_RequestPathSchema(colander.MappingSchema):
    group_name = GroupNameParameter


class User_RequestPathSchema(colander.MappingSchema):
    user_name = UserNameParameter


class UserGroup_RequestPathSchema(colander.MappingSchema):
    user_name = UserNameParameter
    group_name = GroupNameParameter


class GroupService_RequestPathSchema(colander.MappingSchema):
    group_name = GroupNameParameter
    service_name = UserNameParameter


class GroupServicePermission_RequestPathSchema(colander.MappingSchema):
    group_name = GroupNameParameter
    service_name = UserNameParameter
    permission_name = PermissionNameParameter


class GroupResource_RequestPathSchema(colander.MappingSchema):
    group_name = GroupNameParameter
    resource_id = ResourceIdParameter


class GroupResourcePermission_RequestPathSchema(colander.MappingSchema):
    group_name = GroupNameParameter
    resource_id = ResourceIdParameter
    permission_name = PermissionNameParameter


class UserService_RequestPathSchema(colander.MappingSchema):
    user_name = UserNameParameter
    service_name = UserNameParameter


class UserServicePermission_RequestPathSchema(colander.MappingSchema):
    user_name = UserNameParameter
    service_name = UserNameParameter
    permission_name = PermissionNameParameter


class UserResource_RequestPathSchema(colander.MappingSchema):
    user_name = UserNameParameter
    resource_id = ResourceIdParameter


class UserResourcePermission_RequestPathSchema(colander.MappingSchema):
    user_name = UserNameParameter
    resource_id = ResourceIdParameter
    permission_name = PermissionNameParameter


class Provider_RequestPathSchema(colander.MappingSchema):
    provider_name = ProviderNameParameter


class TemporaryURL_RequestPathSchema(colander.MappingSchema):
    token = TokenParameter


# Tags
APITag = "API"
SessionTag = "Session"
UsersTag = "User"
LoggedUserTag = "Logged User"
GroupsTag = "Group"
RegisterTag = "Register"
ResourcesTag = "Resource"
ServicesTag = "Service"

TAG_DESCRIPTIONS = {
    APITag: "General information about the API.",
    SessionTag: "Session user management and available providers for authentication.",
    UsersTag:
        "Users information management and control of their applicable groups, services, resources and permissions.\n\n"
        "Administrator-level permissions are required to access most paths. Depending on context, some paths are "
        "permitted additional access if the logged session user corresponds to the path variable user.",
    LoggedUserTag:
        "Utility paths that correspond to their {} counterparts, but that automatically ".format(UserAPI.path) +
        "determine the applicable user from the logged session. If there is no active session, the public "
        "unauthenticated access is employed.",
    GroupsTag:
        "Groups management and control of their applicable users, services, resources and permissions.\n\n"
        "Administrator-level permissions are required to access most paths. ",
    RegisterTag: "Registration paths for operations available to users (including non-administrators).",
    ResourcesTag: "Management of resources that reside under a given service and their applicable permissions.",
    ServicesTag: "Management of service definitions, children resources and their applicable permissions.",
}

# Header definitions


class AcceptType(colander.SchemaNode):
    schema_type = colander.String
    default = CONTENT_TYPE_JSON
    example = CONTENT_TYPE_JSON
    missing = colander.drop


class ContentType(colander.SchemaNode):
    schema_type = colander.String
    name = "Content-Type"
    default = CONTENT_TYPE_JSON
    example = CONTENT_TYPE_JSON
    missing = colander.drop


class RequestHeaderSchemaAPI(colander.MappingSchema):
    accept = AcceptType(name="Accept", validator=colander.OneOf(SUPPORTED_ACCEPT_TYPES),
                        description="Desired MIME type for the response body content.")
    content_type = ContentType(validator=colander.OneOf(KNOWN_CONTENT_TYPES),
                               description="MIME content type of the request body.")


class RequestHeaderSchemaUI(colander.MappingSchema):
    content_type = ContentType(default=CONTENT_TYPE_HTML, example=CONTENT_TYPE_HTML,
                               description="MIME content type of the request body.")


class QueryRequestSchemaAPI(colander.MappingSchema):
    format = AcceptType(validator=colander.OneOf(SUPPORTED_FORMAT_TYPES),
                        description="Desired MIME type for the response body content. "
                                    "This formatting alternative by query parameter overrides the Accept header.")


QueryEffectivePermissions = colander.SchemaNode(
    colander.Boolean(), name="effective", default=False, missing=colander.drop,
    description="Obtain user's effective permissions resolved with corresponding service inheritance functionality. "
                "(Note: Group inheritance is enforced regardless of 'inherited' query parameter values.)")
QueryInheritGroupsPermissions = colander.SchemaNode(
    colander.Boolean(), name="inherited", default=False, missing=colander.drop,
    description="Include the user's groups memberships inheritance to retrieve all possible permissions. "
                "(Note: Duplicate, redundant or conflicting permissions can be obtained considering applied group"
                " permissions individually. See 'combined' query parameter to resolve such cases.)")
QueryCombinedGroupsPermissions = colander.SchemaNode(
    colander.Boolean(), name="combined", default=False, missing=colander.drop,
    description="Combines corresponding user and groups inherited permissions into one, and locally resolves "
                "for every resource the applicable permission modifiers considering group precedence. "
                "(Note: Group inheritance is enforced regardless of 'inherited' query parameter.)")
QueryFilterResources = colander.SchemaNode(
    colander.Boolean(), name="filtered", default=False, missing=colander.drop,
    description="Filter returned resources only where user has permissions on, either directly or inherited by groups "
                "according to other query parameters. Otherwise (default), return all existing resources "
                "with empty permission sets when user has no permission on them. Filtered view is enforced for "
                "non-admin request user.")
QueryCascadeResourcesPermissions = colander.SchemaNode(
    colander.Boolean(), name="cascade", default=False, missing=colander.drop,
    description="Display all services that has at least one permission at any level in his hierarchy "
                "(including all children resources). Otherwise (default), only returns services that have permissions "
                "explicitly set on them, ignoring permissions set on children resources.")
QueryFlattenServices = colander.SchemaNode(
    colander.Boolean(), name="flatten", default=False, missing=colander.drop,
    description="Return elements as a flattened list of JSON objects instead of default response format. "
                "Default is a nested JSON of service-type keys with children service-name keys, each containing "
                "their respective service definition as JSON object.")


class PhoenixServicePushOption(colander.SchemaNode):
    schema_type = colander.Boolean
    description = "Push service update to Phoenix if applicable"
    missing = colander.drop
    default = False


class BaseRequestSchemaAPI(colander.MappingSchema):
    header = RequestHeaderSchemaAPI()
    querystring = QueryRequestSchemaAPI()


class HeaderResponseSchema(colander.MappingSchema):
    content_type = ContentType(validator=colander.OneOf(SUPPORTED_ACCEPT_TYPES),
                               description="MIME content type of the response body.")


class BaseResponseSchemaAPI(colander.MappingSchema):
    header = HeaderResponseSchema()


class BaseResponseBodySchema(colander.MappingSchema):
    def __init__(self, code, description, **kw):
        super(BaseResponseBodySchema, self).__init__(**kw)
        assert isinstance(code, int)                        # nosec: B101
        assert isinstance(description, six.string_types)    # nosec: B101
        self.__code = code
        self.__desc = description

        # update the values
        child_nodes = getattr(self, "children", [])
        child_nodes.append(colander.SchemaNode(
            colander.Integer(),
            name="code",
            description="HTTP response code",
            example=code))
        child_nodes.append(colander.SchemaNode(
            colander.String(),
            name="type",
            description="Response content type",
            example=CONTENT_TYPE_JSON))
        child_nodes.append(colander.SchemaNode(
            colander.String(),
            name="detail",
            description="Response status message",
            example=description))


class ErrorVerifyParamConditions(colander.MappingSchema):
    not_none = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    not_empty = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    not_in = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    not_equal = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    is_none = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    is_empty = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    is_in = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    is_equal = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    is_true = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    is_false = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    is_type = colander.SchemaNode(colander.Boolean(), missing=colander.drop)
    matches = colander.SchemaNode(colander.Boolean(), missing=colander.drop)


class ErrorVerifyParamBodySchema(colander.MappingSchema):
    name = colander.SchemaNode(
        colander.String(),
        description="Name of the failing condition parameter that caused the error.",
        missing=colander.drop)
    value = colander.SchemaNode(
        colander.String(),
        description="Value of the failing condition parameter that caused the error.",
        default=None)
    compare = colander.SchemaNode(
        colander.String(),
        description="Comparison value(s) employed for evaluation of the failing condition parameter.",
        missing=colander.drop)
    conditions = ErrorVerifyParamConditions(
        description="Evaluated conditions on the parameter value with corresponding validation status. "
                    "Some results are relative to the comparison value when provided.")


class ErrorFallbackBodySchema(colander.MappingSchema):
    exception = colander.SchemaNode(colander.String(), description="Raise exception.")
    error = colander.SchemaNode(colander.String(), description="Error message describing the cause of exception.")


class ErrorCallBodySchema(ErrorFallbackBodySchema):
    detail = colander.SchemaNode(colander.String(), description="Contextual explanation about the cause of error.")
    content = colander.MappingSchema(default=None, unknown="preserve",
                                     description="Additional contextual details that lead to the error. "
                                                 "Can have any amount of sub-field to describe evaluated values.")


class ErrorResponseBodySchema(BaseResponseBodySchema):
    def __init__(self, code, description, **kw):
        super(ErrorResponseBodySchema, self).__init__(code, description, **kw)
        assert code >= 400  # nosec: B101

    route_name = colander.SchemaNode(
        colander.String(),
        description="Route called that generated the error.",
        example="/users/toto")
    request_url = colander.SchemaNode(
        colander.String(),
        title="Request URL",
        description="Request URL that generated the error.",
        example="http://localhost:2001/magpie/users/toto")
    method = colander.SchemaNode(
        colander.String(),
        description="Request method that generated the error.",
        example="GET")
    param = ErrorVerifyParamBodySchema(
        title="Parameter",
        missing=colander.drop,
        description="Additional parameter details to explain the cause of error.")
    call = ErrorCallBodySchema(
        missing=colander.drop,
        description="Additional details to explain failure reason of operation call or raised error.")
    fallback = ErrorFallbackBodySchema(
        missing=colander.drop,
        description="Additional details to explain failure reason of fallback operation to cleanup call error.")


class InternalServerErrorResponseBodySchema(ErrorResponseBodySchema):
    def __init__(self, **kw):
        kw["code"] = HTTPInternalServerError.code
        super(InternalServerErrorResponseBodySchema, self).__init__(**kw)


class BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Required value for request is missing."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class UnauthorizedResponseBodySchema(ErrorResponseBodySchema):
    def __init__(self, **kw):
        kw["code"] = HTTPUnauthorized.code
        super(UnauthorizedResponseBodySchema, self).__init__(**kw)

    route_name = colander.SchemaNode(colander.String(), description="Specified API route.")
    request_url = colander.SchemaNode(colander.String(), description="Specified request URL.")


class UnauthorizedResponseSchema(BaseResponseSchemaAPI):
    description = "Unauthorized access to this resource. Missing authentication headers or cookies."
    body = UnauthorizedResponseBodySchema(code=HTTPUnauthorized.code, description=description)


class HTTPForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Forbidden operation for this resource or insufficient user privileges."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "The route resource could not be found."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class MethodNotAllowedResponseSchema(BaseResponseSchemaAPI):
    description = "The method is not allowed for this resource."
    body = ErrorResponseBodySchema(code=HTTPMethodNotAllowed.code, description=description)


class NotAcceptableResponseSchema(BaseResponseSchemaAPI):
    description = "Unsupported Content-Type in 'Accept' header was specified."
    body = ErrorResponseBodySchema(code=HTTPNotAcceptable.code, description=description)


class UnprocessableEntityResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid value specified."
    body = ErrorResponseBodySchema(code=HTTPUnprocessableEntity.code, description=description)


class InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Internal Server Error. Unhandled exception occurred."
    body = ErrorResponseBodySchema(code=HTTPInternalServerError.code, description=description)


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
    group_name = GroupNameParameter


class UserNamesListSchema(colander.SequenceSchema):
    user_name = UserNameParameter


class Permission_Check_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid permission format. Must be a permission string name or detailed JSON object."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class PermissionObjectSchema(colander.MappingSchema):
    name = colander.SchemaNode(
        colander.String(),
        description="Permission name applicable to the service/resource.",
        example=Permission.READ.value
    )
    access = colander.SchemaNode(
        colander.String(),
        description="Permission access rule to the service/resource.",
        default=Access.ALLOW.value,
        example=Access.ALLOW.value,
    )
    scope = colander.SchemaNode(
        colander.String(),
        description="Permission scope over service/resource tree hierarchy.",
        default=Scope.RECURSIVE.value,
        example=Scope.RECURSIVE.value,
    )


class PermissionObjectTypeSchema(PermissionObjectSchema):
    type = colander.SchemaNode(
        colander.String(),
        description="Permission type being displayed.",
        example=PermissionType.ALLOWED.value,
    )
    reason = colander.SchemaNode(
        colander.String(),
        description="Description of user or group where this permission originated from.",
        example="user:123:my-user",
        missing=colander.drop,
    )


class PermissionObjectListSchema(colander.SequenceSchema):
    permission = PermissionObjectTypeSchema()


class PermissionNameListSchema(colander.SequenceSchema):
    permission_name = colander.SchemaNode(
        colander.String(),
        description="Permissions applicable to the service/resource",
        example=Permission.READ.value
    )


class UserBodySchema(colander.MappingSchema):
    user_name = UserNameParameter
    email = colander.SchemaNode(
        colander.String(),
        description="Email of the user.",
        example="toto@mail.com")
    group_names = GroupNamesListSchema(
        example=["administrators", "users"]
    )


class GroupBaseBodySchema(colander.MappingSchema):
    group_name = colander.SchemaNode(
        colander.String(),
        description="Name of the group.",
        example="Administrators")


class GroupPublicBodySchema(GroupBaseBodySchema):
    # note: use an underscore to differentiate between the node and the parent 'description' metadata
    description = "Publicly available group information."
    _description = colander.SchemaNode(
        colander.String(),
        name="description",
        description="Description associated to the group.",
        example="",
        missing=colander.drop)


class GroupInfoBodySchema(GroupBaseBodySchema):
    description = "Minimal information returned by administrative API routes."
    group_id = colander.SchemaNode(
        colander.Integer(),
        description="ID of the group.",
        example=1)


class GroupDetailBodySchema(GroupPublicBodySchema, GroupInfoBodySchema):
    description = "Detailed information of the group obtained by specifically requesting it."
    member_count = colander.SchemaNode(
        colander.Integer(),
        description="Number of users member of the group.",
        example=2,
        missing=colander.drop)
    user_names = UserNamesListSchema(
        example=["alice", "bob"],
        missing=colander.drop
    )
    discoverable = colander.SchemaNode(
        colander.Boolean(),
        description="Indicates if this group is publicly accessible. "
                    "Discoverable groups can be joined by any logged user.",
        example=True,
        default=False
    )
    priority = colander.SchemaNode(
        colander.Integer(),
        description="Priority order of the group permission resolution, except administrators with enforced 'max'.",
        validator=colander.Range(min=-1, max=None),
        default=0,
        example=0
    )


class ServiceConfigurationSchema(colander.MappingSchema):
    description = "Custom configuration of the service. Expected format and fields specific to each service type."
    missing = colander.drop
    default = colander.null


class ServiceSummarySchema(colander.MappingSchema):
    resource_id = colander.SchemaNode(
        colander.Integer(),
        description="Resource identification number",
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
        missing=colander.drop,  # if listed with corresponding scope (users/groups/admin)
        description="Private URL of the service (restricted access)",
        example="http://localhost:9999/thredds"
    )


class ServiceBodySchema(ServiceSummarySchema):
    permission_names = PermissionNameListSchema(
        description="List of service permissions applicable or effective for a given user/group according to context.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed service permissions applicable or effective for user/group according to context."
    )


class ServiceDetailSchema(ServiceBodySchema):
    configuration = ServiceConfigurationSchema()


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
    permission_names = PermissionNameListSchema(
        description="List of resource permissions applicable or effective for a given user/group according to context.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed resource permissions applicable or effective for user/group according to context."
    )
    permission_names.default = colander.null  # if no parent
    permission_names.missing = colander.drop  # if not returned (basic_info = True)


# FIXME: improve by making recursive resources work (?)
class Resource_ChildrenContainerWithoutChildResourceBodySchema(ResourceBodySchema):
    children = colander.MappingSchema(
        default={},
        description="Recursive '{}' schema for each applicable children resources.".format(ResourceBodySchema.__name__)
    )


class Resource_ChildResourceWithoutChildrenBodySchema(colander.MappingSchema):
    id = Resource_ChildrenContainerWithoutChildResourceBodySchema(name="{resource_id}")


class Resource_ParentResourceWithChildrenContainerBodySchema(ResourceBodySchema):
    children = Resource_ChildResourceWithoutChildrenBodySchema()


class Resource_ChildrenContainerWithChildResourceBodySchema(ResourceBodySchema):
    children = Resource_ChildResourceWithoutChildrenBodySchema()


class Resource_ChildResourceWithChildrenContainerBodySchema(colander.MappingSchema):
    id = Resource_ChildrenContainerWithChildResourceBodySchema(name="{resource_id}")


class Resource_ServiceWithChildrenResourcesContainerBodySchema(ServiceBodySchema):
    resources = Resource_ChildResourceWithChildrenContainerBodySchema()


class Resource_ServiceType_geoserverapi_SchemaNode(colander.MappingSchema):
    geoserver_api = Resource_ServiceWithChildrenResourcesContainerBodySchema(name="geoserver-api")


class Resource_ServiceType_ncwms_SchemaNode(colander.MappingSchema):
    ncwms = Resource_ServiceWithChildrenResourcesContainerBodySchema()


class Resource_ServiceType_thredds_SchemaNode(colander.MappingSchema):
    thredds = Resource_ServiceWithChildrenResourcesContainerBodySchema()


class ResourcesSchemaNode(colander.MappingSchema):
    geoserver_api = Resource_ServiceType_geoserverapi_SchemaNode(name="geoserver-api")
    ncwms = Resource_ServiceType_ncwms_SchemaNode()
    thredds = Resource_ServiceType_thredds_SchemaNode()


class Resources_ResponseBodySchema(BaseResponseBodySchema):
    resources = ResourcesSchemaNode()


class Resource_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Resource_RequestPathSchema()


class Resource_MatchDictCheck_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Resource query by id refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Resource_MatchDictCheck_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Resource ID not found."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class Resource_MatchDictCheck_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Resource ID is an invalid literal for 'int' type."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Resource_GET_ResponseBodySchema(BaseResponseBodySchema):
    resource = Resource_ParentResourceWithChildrenContainerBodySchema()


class Resource_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get resource successful."
    body = Resource_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Resource_GET_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Failed building resource children json formatted tree."
    body = InternalServerErrorResponseBodySchema(code=HTTPInternalServerError.code, description=description)


class Resource_PATCH_RequestBodySchema(colander.MappingSchema):
    resource_name = colander.SchemaNode(
        colander.String(),
        description="New name to apply to the resource to update",
    )
    service_push = PhoenixServicePushOption()


class Resource_PATCH_RequestSchema(BaseRequestSchemaAPI):
    path = Resource_RequestPathSchema()
    body = Resource_PATCH_RequestBodySchema()


class Resource_PATCH_ResponseBodySchema(BaseResponseBodySchema):
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


class Resource_PATCH_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Update resource successful."
    body = Resource_PATCH_ResponseBodySchema(code=HTTPOk.code, description=description)


class Resource_PATCH_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Cannot update resource with provided new name."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Resource_PATCH_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to update resource with new name."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Resource_PATCH_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Resource name already exists at requested tree level for update."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class Resource_DELETE_RequestBodySchema(colander.MappingSchema):
    service_push = PhoenixServicePushOption()


class Resource_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = Resource_RequestPathSchema()
    body = Resource_DELETE_RequestBodySchema()


class Resource_DELETE_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Delete resource successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Resource_DELETE_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Delete resource from db failed."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Resources_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get resources successful."
    body = Resources_ResponseBodySchema(code=HTTPOk.code, description=description)


class Resources_POST_RequestBodySchema(colander.MappingSchema):
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
        colander.Int(),
        description="ID of parent resource under which the new resource should be created",
        missing=colander.drop
    )


class Resources_POST_RequestSchema(BaseRequestSchemaAPI):
    body = Resources_POST_RequestBodySchema()


class Resource_POST_ResponseBodySchema(BaseResponseBodySchema):
    resource = Resource_ChildResourceWithChildrenContainerBodySchema()


class Resources_POST_CreatedResponseSchema(BaseResponseSchemaAPI):
    description = "Create resource successful."
    body = Resource_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class Resources_POST_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid ['resource_name'|'resource_type'|'parent_id'] specified for child resource creation."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Resources_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to insert new resource in service tree using parent id."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Resources_POST_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Could not find specified resource parent id."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class Resources_POST_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Resource name already exists at requested tree level for creation."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class ResourcePermissions_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Resource_RequestPathSchema()


class ResourcePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionNameListSchema(
        description="List of permissions applicable for the referenced resource.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed permissions applicable for the referenced resource."
    )


class ResourcePermissions_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get resource permissions successful."
    body = ResourcePermissions_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ResourcePermissions_GET_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid resource type to extract permissions."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class ServiceResourcesBodySchema(ServiceBodySchema):
    children = ResourcesSchemaNode()


class ServiceType_access_SchemaNode(colander.MappingSchema):
    title = "Services typed for Access"
    description = "These services are all-or-nothing root endpoint access."
    frontend = ServiceBodySchema(missing=colander.drop)
    geoserver_web = ServiceBodySchema(missing=colander.drop, name="geoserver-web")
    magpie = ServiceBodySchema(missing=colander.drop)


class ServiceType_geoserverapi_SchemaNode(colander.MappingSchema):
    name = "geoserver-api"
    title = "Services typed for GeoServer-API"
    geoserver_api = ServiceBodySchema(missing=colander.drop, name="geoserver-api")


class ServiceType_geoserverwms_SchemaNode(colander.MappingSchema):
    title = "Services typed for GeoServer-WMS"
    geoserverwms = ServiceBodySchema(missing=colander.drop)


class ServiceType_ncwms_SchemaNode(colander.MappingSchema):
    title = "Services typed for ncWMS2"
    ncwms = ServiceBodySchema(missing=colander.drop, name="ncWMS2")


class ServiceType_projectapi_SchemaNode(colander.MappingSchema):
    name = "project-api"
    title = "Services typed for Project-API"
    project_api = ServiceBodySchema(missing=colander.drop, name="project-api")


class ServiceType_thredds_SchemaNode(colander.MappingSchema):
    title = "Services typed for Thredds"
    thredds = ServiceBodySchema(missing=colander.drop)


class ServiceType_wfs_SchemaNode(colander.MappingSchema):
    title = "Services typed for WFS"
    geoserver = ServiceBodySchema(missing=colander.drop)


class ServiceType_wps_SchemaNode(colander.MappingSchema):
    title = "Services typed for WPS"
    lb_flyingpigeon = ServiceBodySchema(missing=colander.drop)
    flyingpigeon = ServiceBodySchema(missing=colander.drop)
    project = ServiceBodySchema(missing=colander.drop)
    catalog = ServiceBodySchema(missing=colander.drop)
    malleefowl = ServiceBodySchema(missing=colander.drop)
    hummingbird = ServiceBodySchema(missing=colander.drop)


class ServiceTypesList(colander.SequenceSchema):
    service_type = colander.SchemaNode(
        colander.String(),
        description="Available service type.",
        example="api",
    )


class ServiceListingQuerySchema(QueryRequestSchemaAPI):
    flatten = QueryFlattenServices


class ServiceTypes_GET_RequestSchema(BaseRequestSchemaAPI):
    querystring = ServiceListingQuerySchema()


class ServiceTypes_GET_OkResponseBodySchema(BaseResponseBodySchema):
    service_types = ServiceTypesList(description="List of available service types.")


class ServiceTypes_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get service types successful."
    body = ServiceTypes_GET_OkResponseBodySchema(code=HTTPOk.code, description=description)


class ServicesCategorizedSchemaNode(colander.MappingSchema):
    description = "Registered services categorized by supported service-type. " + \
                  "Listed service-types depend on Magpie version."
    access = ServiceType_access_SchemaNode()
    geoserver_api = ServiceType_geoserverapi_SchemaNode(missing=colander.drop)
    geoserverwms = ServiceType_geoserverwms_SchemaNode(missing=colander.drop)
    ncwms = ServiceType_ncwms_SchemaNode()
    project_api = ServiceType_projectapi_SchemaNode(missing=colander.drop)
    thredds = ServiceType_thredds_SchemaNode()
    wfs = ServiceType_wfs_SchemaNode(missing=colander.drop)
    wps = ServiceType_wps_SchemaNode(missing=colander.drop)


class Service_SummaryBodyResponseSchema(BaseResponseBodySchema):
    service = ServiceSummarySchema()


class Service_SuccessBodyResponseSchema(BaseResponseBodySchema):
    service = ServiceBodySchema()


class Service_DetailBodyResponseSchema(BaseResponseBodySchema):
    service = ServiceDetailSchema()


class ServicesListingSchemaNode(colander.SequenceSchema):
    service = ServiceBodySchema()


class Service_MatchDictCheck_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Service query by name refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Service_MatchDictCheck_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Service name not found."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class Service_CheckConfig_UnprocessableEntityResponseSchema(BaseResponseSchemaAPI):
    description = "Service configuration must be formatted as JSON or null."
    body = ErrorResponseBodySchema(code=HTTPUnprocessableEntity.code, description=description)


Services_GET_RequestSchema = ServiceTypes_GET_RequestSchema


class Service_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Service_RequestPathSchema()


class Service_GET_ResponseBodySchema(BaseResponseBodySchema):
    service = ServiceDetailSchema()


class Service_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get service successful."
    body = Service_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Services_GET_ResponseBodySchema(BaseResponseBodySchema):
    # FIXME: add support schema OneOf(ServicesCategorizedSchemaNode, ServicesListingSchemaNode)
    #        requires https://github.com/fmigneault/cornice.ext.swagger/tree/oneOf-objects
    services = ServicesCategorizedSchemaNode()


class Services_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get services successful."
    body = Services_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Services_GET_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'service_type' value does not correspond to any of the existing service types."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


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
    configuration = ServiceConfigurationSchema()


class Services_POST_RequestBodySchema(BaseRequestSchemaAPI):
    body = Services_POST_BodySchema()


class Services_POST_CreatedResponseSchema(BaseResponseSchemaAPI):
    description = "Service registration to db successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Services_POST_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'service_type' value does not correspond to any of the existing service types."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Services_POST_Params_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid parameter value for service creation."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Services_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Service registration forbidden by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Services_POST_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Specified 'service_name' value already exists."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class Services_POST_UnprocessableEntityResponseSchema(BaseResponseSchemaAPI):
    description = "Service creation for registration failed."
    body = ErrorResponseBodySchema(code=HTTPUnprocessableEntity.code, description=description)


class Services_POST_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Service registration status could not be validated."
    body = ErrorResponseBodySchema(code=HTTPInternalServerError.code, description=description)


class Service_PATCH_RequestBodySchema(colander.MappingSchema):
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
    service_push = PhoenixServicePushOption()
    configuration = ServiceConfigurationSchema()


class Service_PATCH_RequestSchema(BaseRequestSchemaAPI):
    path = Service_RequestPathSchema()
    body = Service_PATCH_RequestBodySchema()


class Service_PATCH_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Update service successful."
    body = Service_DetailBodyResponseSchema(code=HTTPOk.code, description=description)


class Service_PATCH_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Registered service values are already equal to update values."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Service_PATCH_ForbiddenResponseSchema_ReservedKeyword(BaseResponseSchemaAPI):
    description = "Update service name to 'types' not allowed (reserved keyword)."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Service_PATCH_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Update service failed during value assignment."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Service_PATCH_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Specified 'service_name' already exists."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


Service_DELETE_RequestBodySchema = Resource_DELETE_RequestBodySchema


class Service_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = Service_RequestPathSchema()
    body = Service_DELETE_RequestBodySchema()


class Service_DELETE_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Delete service successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Service_DELETE_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Delete service from db refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class ServicePermissions_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionNameListSchema(
        description="List of permissions applicable to the service.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed permissions applicable to the service."
    )


class ServicePermissions_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get service permissions successful."
    path = Service_RequestPathSchema()
    body = ServicePermissions_ResponseBodySchema(code=HTTPOk.code, description=description)


class ServicePermissions_GET_BadRequestResponseBodySchema(ErrorResponseBodySchema):
    service = ServiceBodySchema()


class ServicePermissions_GET_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid service type specified by service."
    body = ServicePermissions_GET_BadRequestResponseBodySchema(code=HTTPBadRequest.code, description=description)


# create service's resource use same method as direct resource create
class ServiceResources_POST_RequestSchema(Resources_POST_RequestSchema):
    path = Service_RequestPathSchema()


ServiceResources_POST_CreatedResponseSchema = Resources_POST_CreatedResponseSchema
ServiceResources_POST_NotFoundResponseSchema = Resources_POST_NotFoundResponseSchema
ServiceResources_POST_ConflictResponseSchema = Resources_POST_ConflictResponseSchema


class ServiceResources_POST_ForbiddenResponseSchema(Resources_POST_ForbiddenResponseSchema):
    description = "Invalid 'parent_id' specified for child resource creation under requested service."


class ServiceResources_POST_UnprocessableEntityResponseSchema(BaseResponseSchemaAPI):
    description = "Provided 'parent_id' value is invalid."
    body = ErrorResponseBodySchema(code=HTTPUnprocessableEntity.code, description=description)


# delete service's resource use same method as direct resource delete
class ServiceResource_DELETE_RequestSchema(Resource_DELETE_RequestSchema):
    service_name = ServiceNameParameter


ServiceResource_DELETE_ForbiddenResponseSchema = Resource_DELETE_ForbiddenResponseSchema
ServiceResource_DELETE_OkResponseSchema = Resource_DELETE_OkResponseSchema


class ServiceResources_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Service_RequestPathSchema()


class ServiceResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    service_name = Resource_ServiceWithChildrenResourcesContainerBodySchema(name="{service_name}")


class ServiceResources_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get service resources successful."
    body = ServiceResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ServiceTypeResources_GET_RequestSchema(BaseRequestSchemaAPI):
    path = ServiceType_RequestPathSchema()


class ServiceTypeResourceInfo(colander.MappingSchema):
    resource_type = colander.SchemaNode(
        colander.String(),
        description="Resource type."
    )
    resource_child_allowed = colander.SchemaNode(
        colander.Boolean(),
        description="Indicates if the resource type allows child resources."
    )
    permission_names = PermissionNameListSchema(
        description="Permissions applicable to the specific resource type.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed permissions applicable to the specific resource type."
    )


class ServiceTypeResourcesList(colander.SequenceSchema):
    resource_type = ServiceTypeResourceInfo(description="Resource type detail for specific service type.")


class ServiceTypeResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    resource_types = ServiceTypeResourcesList(description="Supported resources types under specific service type.")


class ServiceTypeResources_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get service type resources successful."
    body = ServiceTypeResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ServiceTypeResources_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to obtain resource types for specified service type."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class ServiceTypeResources_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'service_type' does not exist to obtain its resource types."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class ServiceTypeResourceTypes_GET_RequestSchema(BaseRequestSchemaAPI):
    path = ServiceType_RequestPathSchema()


class ServiceTypeResourceTypes_GET_ResponseBodySchema(BaseResponseBodySchema):
    resource_types = ResourceTypesListSchema()


class ServiceTypeResourceTypes_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get service type resource types successful."
    body = ServiceTypeResourceTypes_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ServiceTypeResourceTypes_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to obtain resource types for specified service type."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class ServiceTypeResourceTypes_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'service_type' does not exist to obtain its resource types."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class Users_GET_ResponseBodySchema(BaseResponseBodySchema):
    user_names = UserNamesListSchema()


class Users_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get users successful."
    body = Users_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Users_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Get users query refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Users_CheckInfo_UserNameValue_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'user_name' value specified."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_UserNameSize_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'user_name' length specified (>{length} characters)." \
                  .format(length=get_constant("MAGPIE_USER_NAME_MAX_LENGTH"))
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_Email_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'email' value specified."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_PasswordValue_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'password' value specified."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_PasswordSize_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'password' length specified (<{length} characters)." \
                  .format(length=get_constant("MAGPIE_PASSWORD_MIN_LENGTH"))
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_GroupName_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'group_name' value specified."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Users_CheckInfo_ReservedKeyword_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'user_name' not allowed (reserved keyword)."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


# alias for readability across code, but we actually do the same check
User_Check_BadRequestResponseSchema = Users_CheckInfo_UserNameValue_BadRequestResponseSchema


class User_Check_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "User check query was refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_Check_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "User name matches an already existing user name."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


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


class Users_POST_RequestSchema(BaseRequestSchemaAPI):
    body = User_POST_RequestBodySchema()


class Users_POST_ResponseBodySchema(BaseResponseBodySchema):
    user = UserBodySchema()


class Users_POST_CreatedResponseSchema(BaseResponseSchemaAPI):
    description = "Add user to db successful."
    body = Users_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class Users_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to add user to db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserNew_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "New user query was refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_PATCH_RequestBodySchema(colander.MappingSchema):
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


class User_PATCH_RequestSchema(BaseRequestSchemaAPI):
    path = User_RequestPathSchema()
    body = User_PATCH_RequestBodySchema()


class Users_PATCH_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Update user successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class User_PATCH_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Missing new user parameters to update."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class User_PATCH_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Targeted user update not allowed by requesting user."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_PATCH_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "New name user already exists."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class User_GET_RequestSchema(BaseRequestSchemaAPI):
    path = User_RequestPathSchema()


class User_GET_ResponseBodySchema(BaseResponseBodySchema):
    user = UserBodySchema()


class User_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get user successful."
    body = User_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class User_CheckAnonymous_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Anonymous user query refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_CheckAnonymous_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Anonymous user not found."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class User_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "User access forbidden for this resource."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_GET_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "User name query refused by db."
    body = ErrorResponseBodySchema(code=HTTPInternalServerError.code, description=description)


class User_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "User name not found."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class User_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = User_RequestPathSchema()
    body = colander.MappingSchema(default={})


class User_DELETE_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Delete user successful."
    body = BaseResponseBodySchema(code=HTTPForbidden.code, description=description)


class User_DELETE_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "User could not be deleted."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroups_GET_RequestSchema(BaseRequestSchemaAPI):
    path = User_RequestPathSchema()


class UserGroups_GET_ResponseBodySchema(BaseResponseBodySchema):
    group_names = GroupNamesListSchema()


class UserGroups_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get user groups successful."
    body = UserGroups_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserGroups_POST_RequestBodySchema(colander.MappingSchema):
    group_name = colander.SchemaNode(
        colander.String(),
        description="Name of the group in the user-group relationship",
        example="users",
    )


class UserGroups_POST_RequestSchema(BaseRequestSchemaAPI):
    path = User_RequestPathSchema()
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


class UserGroups_POST_CreatedResponseSchema(BaseResponseSchemaAPI):
    description = "Create user-group assignation successful. User is a member of the group."
    body = UserGroups_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class UserGroups_POST_GroupNotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Cannot find the group to assign to."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserGroups_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Group query by name refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroups_POST_RelationshipForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "User-Group relationship creation refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroups_POST_ConflictResponseBodySchema(ErrorResponseBodySchema):
    param = ErrorVerifyParamBodySchema()
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


class UserGroups_POST_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "User already belongs to this group."
    body = UserGroups_POST_ConflictResponseBodySchema(code=HTTPConflict.code, description=description)


class UserGroup_Check_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid group name to associate to user."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class UserGroup_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Group query was refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroup_Check_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Group for new user doesn't exist."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class UserGroup_Check_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to add user-group to db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroup_DELETE_RequestSchema(BaseRequestSchemaAPI):
    body = colander.MappingSchema(default={})


class UserGroup_DELETE_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Delete user-group successful. User is not a member of the group anymore."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class UserGroup_DELETE_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Delete user-group relationship not permitted for this combination."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserGroup_DELETE_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Could not remove user from group. Could not find any matching group membership for user."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResources_GET_QuerySchema(QueryRequestSchemaAPI):
    inherited = QueryInheritGroupsPermissions
    combined = QueryCombinedGroupsPermissions
    filtered = QueryFilterResources


class UserResources_GET_RequestSchema(BaseRequestSchemaAPI):
    path = User_RequestPathSchema()
    querystring = UserResources_GET_QuerySchema()


class UserResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    resources = ResourcesSchemaNode()


class UserResources_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get user resources successful."
    body = UserResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserResources_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to populate user resources."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResourcePermissions_Check_ParamResponseBodySchema(colander.MappingSchema):
    name = colander.SchemaNode(colander.String(), description="Specified parameter.", example="permission_name")
    value = colander.SchemaNode(colander.String(), description="Specified parameter value.")


class UserResourcePermissions_Check_ErrorResponseBodySchema(ErrorResponseBodySchema):
    user_name = colander.SchemaNode(colander.String(), description="Specified user name.")
    resource_id = colander.SchemaNode(colander.String(), description="Specified service/resource id.")
    permission_name = colander.SchemaNode(colander.String(), description="Specified permission name.")
    permission = PermissionObjectTypeSchema(description="Specific permission extended definition.")
    param = UserResourcePermissions_Check_ParamResponseBodySchema(missing=colander.drop)


class UserResourcePermissions_Check_ErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Lookup of similar permission on service/resource for user refused by db."
    body = UserResourcePermissions_Check_ErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description
    )


class UserResourcePermissions_GET_QuerySchema(QueryRequestSchemaAPI):
    inherited = QueryInheritGroupsPermissions
    combined = QueryCombinedGroupsPermissions
    effective = QueryEffectivePermissions


class UserResourcePermissions_GET_RequestSchema(BaseRequestSchemaAPI):
    path = UserResource_RequestPathSchema()
    querystring = UserResourcePermissions_GET_QuerySchema()


class UserResourcePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionNameListSchema(
        description="List of resource permissions applied or effective for the referenced user.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed resource permissions applied or effective to the referenced user."
    )


class UserResourcePermissions_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get user resource permissions successful."
    body = UserResourcePermissions_GET_ResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResourcePermissions_GET_BadRequestParamResponseSchema(colander.MappingSchema):
    name = colander.SchemaNode(colander.String(), description="name of the parameter tested", example="resource_type")
    value = colander.SchemaNode(colander.String(), description="value of the parameter tested")
    compare = colander.SchemaNode(colander.String(), description="comparison value of the parameter tested",
                                  missing=colander.drop)


class UserResourcePermissions_GET_BadRequestResponseBodySchema(colander.MappingSchema):
    param = UserResourcePermissions_GET_BadRequestParamResponseSchema()


class UserResourcePermissions_GET_BadRequestRootServiceResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'resource' specified for resource permission retrieval."
    body = UserResourcePermissions_GET_BadRequestResponseBodySchema(
        code=HTTPBadRequest.code, description=description)


class UserResourcePermissions_GET_BadRequestResourceResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'resource' specified for resource permission retrieval."
    body = UserResourcePermissions_GET_BadRequestResponseBodySchema(
        code=HTTPBadRequest.code, description=description)


class UserResourcePermissions_GET_BadRequestResourceTypeResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'resource_type' for corresponding service resource permission retrieval."
    body = UserResourcePermissions_GET_BadRequestResponseBodySchema(
        code=HTTPBadRequest.code, description=description)


class UserResourcePermissions_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Specified user or resource not found to obtain permissions."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResourcePermissions_POST_RequestBodySchema(colander.MappingSchema):
    permission_name = colander.SchemaNode(
        colander.String(),
        description="Permission name (implicit or explicit) to create on the resource for the user.",
        missing=colander.drop
    )
    permission = PermissionObjectSchema(
        description="Detailed permission definition to create on the resource for the user.",
        missing=colander.drop
    )


class UserResourcePermissions_POST_RequestSchema(BaseRequestSchemaAPI):
    path = UserResource_RequestPathSchema()
    body = UserResourcePermissions_POST_RequestBodySchema()


UserResourcePermissions_PUT_RequestSchema = UserResourcePermissions_POST_RequestSchema


class UserResourcePermissions_POST_ResponseBodySchema(BaseResponseBodySchema):
    resource_id = colander.SchemaNode(
        colander.Integer(),
        description="Resource for which to create the user permission."
    )
    user_id = colander.SchemaNode(
        colander.Integer(),
        description="User for which to create the permission on the resource."
    )
    permission_name = colander.SchemaNode(
        colander.String(),
        description="Permission name (implicit or explicit) to create on the resource for the user.",
        missing=colander.drop
    )
    permission = PermissionObjectSchema(
        description="Detailed permission definition to create on the resource for the user.",
        missing=colander.drop
    )


class UserResourcePermissions_POST_CreatedResponseSchema(BaseResponseSchemaAPI):
    description = "Create user resource permission successful."
    body = UserResourcePermissions_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class UserResourcePermissions_POST_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Permission not allowed for specified 'resource_type'."
    body = UserResourcePermissions_Check_ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class UserResourcePermissions_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Creation of permission on resource for user refused by db."
    body = UserResourcePermissions_Check_ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class UserResourcePermissions_POST_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Similar permission already exist on resource for user."
    body = UserResourcePermissions_Check_ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class UserResourcePermissions_PUT_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Update user resource permission successful."
    body = UserResourcePermissions_POST_ResponseBodySchema(code=HTTPOk.code, description=description)


UserResourcePermissions_PUT_CreatedResponseSchema = UserResourcePermissions_POST_CreatedResponseSchema
UserResourcePermissions_PUT_BadRequestResponseSchema = UserResourcePermissions_POST_BadRequestResponseSchema
UserResourcePermissions_PUT_ForbiddenResponseSchema = UserResourcePermissions_POST_ForbiddenResponseSchema


# using same definitions
UserResourcePermissionName_DELETE_ErrorResponseBodySchema = UserResourcePermissions_Check_ErrorResponseBodySchema
UserResourcePermissionName_DELETE_BadRequestResponseSchema = UserResourcePermissions_POST_BadRequestResponseSchema


class UserResourcePermissionName_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = UserResourcePermission_RequestPathSchema()
    body = colander.MappingSchema(default={})


class UserResourcePermissionName_DELETE_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Delete user resource permission successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class UserResourcePermissionName_DELETE_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Could not find user resource permission to delete from db."
    body = UserResourcePermissionName_DELETE_ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class UserResourcePermissions_DELETE_RequestBodySchema(colander.MappingSchema):
    permission = PermissionObjectSchema(description="Permission to be deleted.")


class UserResourcePermissions_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = UserResource_RequestPathSchema()
    body = UserResourcePermissions_DELETE_RequestBodySchema()


UserResourcePermissions_DELETE_OkResponseSchema = UserResourcePermissionName_DELETE_OkResponseSchema
UserResourcePermissions_DELETE_BadRequestResponseSchema = UserResourcePermissionName_DELETE_BadRequestResponseSchema
UserResourcePermissions_DELETE_NotFoundResponseSchema = UserResourcePermissionName_DELETE_NotFoundResponseSchema


class UserServiceResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    service = ServiceResourcesBodySchema()


class UserServiceResources_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get user service resources successful."
    body = UserServiceResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserServiceResources_GET_QuerySchema(QueryRequestSchemaAPI):
    inherited = QueryInheritGroupsPermissions
    combined = QueryCombinedGroupsPermissions


class UserServiceResources_GET_RequestSchema(BaseRequestSchemaAPI):
    path = UserService_RequestPathSchema()
    querystring = UserServiceResources_GET_QuerySchema()


class UserServicePermissions_POST_RequestBodySchema(colander.MappingSchema):
    permission_name = colander.SchemaNode(
        colander.String(),
        description="Permission name (implicit or explicit) to create on the service for the user.",
        missing=colander.drop
    )
    permission = PermissionObjectSchema(
        description="Detailed permission definition to create on the service for the user.",
        missing=colander.drop
    )


class UserServicePermissions_POST_RequestSchema(BaseRequestSchemaAPI):
    path = UserService_RequestPathSchema()
    body = UserServicePermissions_POST_RequestBodySchema()


UserServicePermissions_PUT_RequestSchema = UserServicePermissions_POST_RequestSchema


class UserServicePermissions_DELETE_RequestBodySchema(colander.MappingSchema):
    permission = PermissionObjectSchema(description="Permission to be deleted.")


class UserServicePermissions_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = UserService_RequestPathSchema()
    body = UserResourcePermissions_DELETE_RequestBodySchema()


class UserServicePermissionName_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = UserServicePermission_RequestPathSchema()
    body = colander.MappingSchema(default={})


class UserServices_GET_QuerySchema(QueryRequestSchemaAPI):
    cascade = QueryCascadeResourcesPermissions
    inherit = QueryInheritGroupsPermissions
    flatten = QueryFlattenServices


class UserServices_GET_RequestSchema(BaseRequestSchemaAPI):
    path = User_RequestPathSchema()
    querystring = UserServices_GET_QuerySchema()


class UserServices_GET_ResponseBodySchema(BaseResponseBodySchema):
    services = ServicesCategorizedSchemaNode()


class UserServices_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get user services successful."
    body = UserServices_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserServicePermissions_GET_QuerySchema(QueryRequestSchemaAPI):
    inherited = QueryInheritGroupsPermissions
    combined = QueryCombinedGroupsPermissions


class UserServicePermissions_GET_RequestSchema(BaseRequestSchemaAPI):
    path = UserService_RequestPathSchema()
    querystring = UserServicePermissions_GET_QuerySchema()


class UserServicePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionNameListSchema(
        description="List of service permissions applied or effective for the referenced user.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed service permissions applied or effective to the referenced user."
    )


class UserServicePermissions_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get user service permissions successful."
    body = UserServicePermissions_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class UserServicePermissions_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Could not find permissions using specified 'service_name' and 'user_name'."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class Group_MatchDictCheck_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Group query by name refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Group_MatchDictCheck_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Group name not found."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class Groups_CheckInfo_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "User name not found."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class Groups_CheckInfo_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to obtain groups of user."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Groups_GET_ResponseBodySchema(BaseResponseBodySchema):
    group_names = GroupNamesListSchema()


class Groups_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get groups successful."
    body = Groups_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Groups_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Obtain group names refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Groups_POST_RequestBodySchema(colander.MappingSchema):
    group_name = colander.SchemaNode(colander.String(), description="Name of the group to create.")
    description = colander.SchemaNode(colander.String(), default="",
                                      description="Description to apply to the created group.")
    discoverable = colander.SchemaNode(colander.Boolean(), default=False,
                                       description="Discoverability status of the created group.")


class Groups_POST_RequestSchema(BaseRequestSchemaAPI):
    body = Groups_POST_RequestBodySchema()


class Groups_POST_ResponseBodySchema(BaseResponseBodySchema):
    group = GroupInfoBodySchema()


class Groups_POST_CreatedResponseSchema(BaseResponseSchemaAPI):
    description = "Create group successful."
    body = Groups_POST_ResponseBodySchema(code=HTTPCreated.code, description=description)


class Groups_POST_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid parameter for group creation."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Groups_POST_ForbiddenCreateResponseSchema(BaseResponseSchemaAPI):
    description = "Create new group by name refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Groups_POST_ForbiddenAddResponseSchema(BaseResponseSchemaAPI):
    description = "Add new group by name refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Groups_POST_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Group name matches an already existing group name."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class Group_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()


class Group_GET_ResponseBodySchema(BaseResponseBodySchema):
    group = GroupDetailBodySchema()


class Group_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get group successful."
    body = Group_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Group_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Group name was not found."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class Group_PATCH_RequestBodySchema(colander.MappingSchema):
    group_name = colander.SchemaNode(colander.String(), missing=colander.drop,
                                     description="New name to apply to the group.")
    description = colander.SchemaNode(colander.String(), missing=colander.drop,
                                      description="New description to apply to the group.")
    discoverable = colander.SchemaNode(colander.Boolean(), missing=colander.drop,
                                       description="New discoverable status to apply to the group.")


class Group_PATCH_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()
    body = Group_PATCH_RequestBodySchema()


class Group_PATCH_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Update group successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Group_PATCH_None_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Missing new group parameters to update."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Group_PATCH_Name_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'group_name' value specified."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Group_PATCH_Size_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'group_name' length specified (>{length} characters)." \
        .format(length=get_constant("MAGPIE_USER_NAME_MAX_LENGTH"))
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Group_PATCH_ReservedKeyword_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Update of reserved keyword or special group forbidden."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Group_PATCH_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Group name already exists."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class Group_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()
    body = colander.MappingSchema(default={})


class Group_DELETE_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Delete group successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Group_DELETE_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Delete group forbidden by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Group_DELETE_ReservedKeyword_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Deletion of reserved keyword or special group forbidden."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupUsers_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()


class GroupUsers_GET_ResponseBodySchema(BaseResponseBodySchema):
    user_names = UserNamesListSchema()


class GroupUsers_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get group users successful."
    body = GroupUsers_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupUsers_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to obtain group user names from db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupServices_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()


class GroupServices_GET_ResponseBodySchema(BaseResponseBodySchema):
    services = ServicesCategorizedSchemaNode()


class GroupServices_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get group services successful."
    body = GroupServices_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServices_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = GroupInfoBodySchema()


class GroupServices_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to populate group services."
    body = GroupServices_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupServicePermissions_GET_RequestSchema(BaseRequestSchemaAPI):
    path = GroupService_RequestPathSchema()


class GroupServicePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permission_names = PermissionNameListSchema(
        description="List of service permissions applied to the referenced group.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed service permissions applied to the referenced group."
    )


class GroupServicePermissions_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get group service permissions successful."
    body = GroupServicePermissions_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServicePermissions_GET_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = GroupInfoBodySchema()
    service = ServiceBodySchema()


class GroupServicePermissions_GET_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to extract permissions names from group-service."
    body = GroupServicePermissions_GET_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupServicePermissions_POST_RequestBodySchema(colander.MappingSchema):
    permission_name = colander.SchemaNode(
        colander.String(),
        description="Permission name (implicit or explicit) to create on the service for the group.",
        missing=colander.drop
    )
    permission = PermissionObjectSchema(
        description="Detailed permission definition to create on the service for the group.",
        missing=colander.drop
    )


class GroupServicePermissions_POST_RequestSchema(BaseRequestSchemaAPI):
    path = GroupService_RequestPathSchema()
    body = GroupServicePermissions_POST_RequestBodySchema()


class GroupResourcePermissions_POST_RequestSchema(BaseRequestSchemaAPI):
    path = GroupResource_RequestPathSchema()
    body = GroupServicePermissions_POST_RequestBodySchema()


class GroupResourcePermissions_Check_ResponseBodySchema(BaseResponseBodySchema):
    permission_name = colander.SchemaNode(colander.String(), description="Name of the permission requested.")
    permission = PermissionObjectTypeSchema(description="Detailed permission definition.")
    resource = ResourceBodySchema()
    group = GroupInfoBodySchema()


class GroupResourcePermissions_Check_ErrorResponseBodySchema(ErrorResponseBodySchema):
    pass


class GroupResourcePermissions_Check_ErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Lookup of similar permission on service/resource for group refused by db."
    body = GroupResourcePermissions_Check_ErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description
    )


class GroupResourcePermissions_POST_CreatedResponseSchema(BaseResponseSchemaAPI):
    description = "Create group resource permission successful."
    body = GroupResourcePermissions_Check_ResponseBodySchema(code=HTTPCreated.code, description=description)


class GroupResourcePermissions_POST_ForbiddenAddResponseSchema(BaseResponseSchemaAPI):
    description = "Add group resource permission refused by db."
    body = GroupResourcePermissions_Check_ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupResourcePermissions_POST_ForbiddenCreateResponseSchema(BaseResponseSchemaAPI):
    description = "Create group resource permission failed."
    body = GroupResourcePermissions_Check_ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupResourcePermissions_POST_ForbiddenGetResponseSchema(BaseResponseSchemaAPI):
    description = "Get group resource permission failed."
    body = GroupResourcePermissions_Check_ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupResourcePermissions_POST_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Similar permission already exists on resource for group."
    body = GroupResourcePermissions_Check_ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


GroupResourcePermissions_PUT_RequestSchema = GroupResourcePermissions_POST_RequestSchema
GroupResourcePermissions_PUT_CreatedResponseSchema = GroupResourcePermissions_POST_CreatedResponseSchema
GroupResourcePermissions_PUT_ForbiddenResponseSchema = GroupResourcePermissions_POST_ForbiddenGetResponseSchema


class GroupResourcePermissions_PUT_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Update group resource permission successful."
    body = GroupResourcePermissions_Check_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupResourcePermissionName_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = GroupResourcePermission_RequestPathSchema()
    body = colander.MappingSchema(default={})


class GroupResourcePermissions_DELETE_RequestBodySchema(colander.MappingSchema):
    permission = PermissionObjectSchema(
        description="Detailed permission definition to delete from the resource for the group.",
        missing=colander.drop
    )


class GroupResourcePermissions_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = GroupResource_RequestPathSchema()
    body = GroupResourcePermissions_DELETE_RequestBodySchema()


class GroupResourcesPermissions_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = colander.SchemaNode(colander.String(), description="Object representation of the group.")
    resource_ids = colander.SchemaNode(colander.String(), description="Object representation of the resource ids.")
    resource_types = colander.SchemaNode(colander.String(), description="Object representation of the resource types.")


class GroupResourcesPermissions_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to build group resources json tree."
    body = GroupResourcesPermissions_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupResourcePermissions_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = colander.SchemaNode(colander.String(), description="Object representation of the group.")
    resource = colander.SchemaNode(colander.String(), description="Object representation of the resource.")


class GroupResourcePermissions_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to obtain group resource permissions."
    body = GroupResourcePermissions_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupResources_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()


class GroupResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    resources = ResourcesSchemaNode()


class GroupResources_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get group resources successful."
    body = GroupResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupResources_GET_InternalServerErrorResponseBodySchema(InternalServerErrorResponseBodySchema):
    group = colander.SchemaNode(colander.String(), description="Object representation of the group.")


class GroupResources_GET_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to build group resources json tree."
    body = GroupResources_GET_InternalServerErrorResponseBodySchema(
        code=HTTPInternalServerError.code, description=description)


class GroupResourcePermissions_GET_RequestSchema(BaseRequestSchemaAPI):
    path = GroupResource_RequestPathSchema()


class GroupResourcePermissions_GET_ResponseBodySchema(BaseResponseBodySchema):
    permissions_names = PermissionNameListSchema(
        description="List of resource permissions applied to the referenced group.",
        example=[Permission.READ.value, Permission.WRITE.value]
    )
    permissions = PermissionObjectListSchema(
        description="List of detailed resource permissions applied to the referenced group."
    )


class GroupResourcePermissions_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get group resource permissions successful."
    body = GroupResourcePermissions_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServiceResources_GET_RequestSchema(BaseRequestSchemaAPI):
    path = GroupService_RequestPathSchema()


class GroupServiceResources_GET_ResponseBodySchema(BaseResponseBodySchema):
    service = ServiceResourcesBodySchema()


class GroupServiceResources_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get group service resources successful."
    body = GroupServiceResources_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


GroupServicePermissions_PUT_RequestSchema = GroupServicePermissions_POST_RequestSchema
GroupServicePermissions_DELETE_RequestSchema = GroupResourcePermissions_DELETE_RequestSchema


class GroupServicePermission_DELETE_RequestBodySchema(colander.MappingSchema):
    permission_name = colander.SchemaNode(colander.String(), description="Name of the permission to delete.")


class GroupServicePermissionName_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = GroupServicePermission_RequestPathSchema()
    body = GroupServicePermission_DELETE_RequestBodySchema()


class GroupServicePermission_DELETE_ResponseBodySchema(BaseResponseBodySchema):
    group = GroupInfoBodySchema()
    resource = ResourceBodySchema()
    permission_name = colander.SchemaNode(
        colander.String(),
        description="Permission name (implicit or explicit) to be created.",
        missing=colander.drop
    )
    permission = PermissionObjectSchema(
        description="Detailed permission to be created",
        missing=colander.drop
    )


class GroupServicePermission_DELETE_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Delete group resource permission successful."
    body = GroupServicePermission_DELETE_ResponseBodySchema(code=HTTPOk.code, description=description)


class GroupServicePermission_DELETE_ForbiddenGetResponseSchema(BaseResponseSchemaAPI):
    description = "Get group resource permission failed."
    body = GroupServicePermission_DELETE_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupServicePermission_DELETE_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Delete group resource permission refused by db."
    body = GroupServicePermission_DELETE_ResponseBodySchema(code=HTTPForbidden.code, description=description)


class GroupServicePermission_DELETE_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Permission not found for corresponding group and resource."
    body = GroupServicePermission_DELETE_ResponseBodySchema(code=HTTPNotFound.code, description=description)


class RegisterGroup_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Could not find any discoverable group matching provided name."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class RegisterGroups_GET_ResponseBodySchema(BaseResponseBodySchema):
    group_names = GroupNamesListSchema(description="List of discoverable group names.")


class RegisterGroups_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get discoverable groups successful."
    body = RegisterGroups_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class RegisterGroups_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Obtain discoverable groups refused by db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class RegisterGroup_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()


class RegisterGroup_GET_ResponseBodySchema(BaseResponseBodySchema):
    group = GroupPublicBodySchema()  # not detailed because authenticated route has limited information


class RegisterGroup_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get discoverable group successful."
    body = RegisterGroup_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class RegisterGroup_POST_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()
    body = colander.MappingSchema(description="Nothing required.")


class RegisterGroup_POST_ResponseBodySchema(BaseResponseBodySchema):
    user_name = colander.SchemaNode(
        colander.String(),
        description="Name of the user in the user-group relationship.",
        example="logged-user",
    )
    group_name = colander.SchemaNode(
        colander.String(),
        description="Name of the group in the user-group relationship.",
        example="public-group",
    )


class RegisterGroup_POST_CreatedResponseSchema(BaseResponseSchemaAPI):
    description = "Logged user successfully joined the discoverable group. User is now a member of the group."
    body = RegisterGroup_POST_ResponseBodySchema(code=HTTPNotFound.code, description=description)


class RegisterGroup_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Group membership was not permitted for the logged user."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class RegisterGroup_POST_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Logged user is already a member of the group."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class RegisterGroup_DELETE_RequestSchema(BaseRequestSchemaAPI):
    path = Group_RequestPathSchema()
    body = colander.MappingSchema(description="Nothing required.")


class RegisterGroup_DELETE_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Logged user successfully removed from the group. User is not a member of the group anymore."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


# check done using same util function
RegisterGroup_DELETE_ForbiddenResponseSchema = UserGroup_DELETE_ForbiddenResponseSchema
RegisterGroup_DELETE_NotFoundResponseSchema = UserGroup_DELETE_NotFoundResponseSchema


class TemporaryURL_GET_RequestSchema(BaseRequestSchemaAPI):
    path = TemporaryURL_RequestPathSchema()


class TemporaryURL_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Successful operation from provided temporary URL token."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class TemporaryURL_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Could not find any operation matching temporary URL token."
    body = ErrorResponseBodySchema(code=HTTPNotFound.code, description=description)


class TemporaryURL_GET_GoneResponseSchema(BaseResponseSchemaAPI):
    description = "Temporary URL token is expired."
    body = BaseResponseBodySchema(code=HTTPGone.code, description=description)


class TemporaryToken_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to add token to db."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Session_GET_ResponseBodySchema(BaseResponseBodySchema):
    user = UserBodySchema(missing=colander.drop)
    authenticated = colander.SchemaNode(
        colander.Boolean(),
        description="Indicates if any user session is currently authenticated (user logged in).")


class Session_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get session successful."
    body = Session_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Session_GET_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Failed to get session details."
    body = InternalServerErrorResponseSchema()


class ProvidersBodySchema(colander.MappingSchema):
    internal = ProvidersListSchema()
    external = ProvidersListSchema()


class Providers_GET_ResponseBodySchema(BaseResponseBodySchema):
    providers = ProvidersBodySchema()


class Providers_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get providers successful."
    body = Providers_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class ProviderSignin_GET_RequestHeaderSchema(RequestHeaderSchemaAPI):
    Authorization = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        example="Bearer MyF4ncy4ccEsT0k3n",
        description="Access token to employ for direct signin with external provider bypassing the login procedure. "
                    "Access token must have been validated with the corresponding provider beforehand. "
                    "Supported format is 'Authorization: Bearer MyF4ncy4ccEsT0k3n'")
    HomepageRoute = colander.SchemaNode(
        colander.String(),
        missing=colander.drop,
        example="/session",
        default="Magpie UI Homepage",
        name="Homepage-Route",
        description="Alternative redirection homepage after signin. "
                    "Must be a relative path to Magpie for security reasons.")


class ProviderSignin_GET_RequestSchema(BaseRequestSchemaAPI):
    path = Provider_RequestPathSchema()
    header = ProviderSignin_GET_RequestHeaderSchema()


class ProviderSignin_GET_FoundResponseBodySchema(BaseResponseBodySchema):
    homepage_route = colander.SchemaNode(colander.String(), description="Route to be used for following redirection.")


class ProviderSignin_GET_FoundResponseSchema(BaseResponseSchemaAPI):
    description = "External login homepage route found. Temporary status before redirection to 'Homepage-Route' header."
    body = ProviderSignin_GET_FoundResponseBodySchema(code=HTTPFound.code, description=description)


class ProviderSignin_GET_BadRequestResponseBodySchema(ErrorResponseBodySchema):
    reason = colander.SchemaNode(colander.String(), description="Additional detail about the error.")


class ProviderSignin_GET_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Incorrectly formed 'Authorization: Bearer <access_token>' header."
    body = ProviderSignin_GET_BadRequestResponseBodySchema(code=HTTPBadRequest.code, description=description)


class ProviderSignin_GET_UnauthorizedResponseSchema(BaseResponseSchemaAPI):
    description = "Unauthorized 'UserInfo' update using provided Authorization headers."
    body = ErrorResponseBodySchema(code=HTTPUnauthorized.code, description=description)


class ProviderSignin_GET_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Forbidden 'Homepage-Route' host not matching Magpie refused for security reasons."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class ProviderSignin_GET_NotFoundResponseBodySchema(ErrorResponseBodySchema):
    param = ErrorVerifyParamBodySchema()
    provider_name = colander.SchemaNode(colander.String())
    providers = ProvidersListSchema()


class ProviderSignin_GET_NotFoundResponseSchema(BaseResponseSchemaAPI):
    description = "Invalid 'provider_name' not found within available providers."
    body = ProviderSignin_GET_NotFoundResponseBodySchema(code=HTTPNotFound.code, description=description)


class Signin_BaseRequestSchema(colander.MappingSchema):
    user_name = colander.SchemaNode(colander.String(),
                                    description="User name to use for sign in. "
                                                "Can also be the email provided during registration.")
    password = colander.SchemaNode(colander.String(), description="Password to use for sign in.")
    provider_name = colander.SchemaNode(colander.String(),
                                        description="Provider to use for sign in. "
                                                    "Required for external provider login.",
                                        default=get_constant("MAGPIE_DEFAULT_PROVIDER"), missing=colander.drop)


class SigninQueryParamSchema(QueryRequestSchemaAPI, Signin_BaseRequestSchema):
    pass


class Signin_GET_RequestSchema(BaseRequestSchemaAPI):
    querystring = SigninQueryParamSchema()


class Signin_POST_RequestSchema(BaseRequestSchemaAPI):
    body = Signin_BaseRequestSchema()


class Signin_POST_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Login successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Signin_POST_BadRequestResponseSchema(BaseResponseSchemaAPI):
    description = "Missing credentials."
    body = ErrorResponseBodySchema(code=HTTPBadRequest.code, description=description)


class Signin_POST_UnauthorizedResponseSchema(BaseResponseSchemaAPI):
    description = "Incorrect credentials."
    body = ErrorResponseBodySchema(code=HTTPUnauthorized.code, description=description)


class Signin_POST_ForbiddenResponseSchema(BaseResponseSchemaAPI):
    description = "Could not verify 'user_name'."
    body = ErrorResponseBodySchema(code=HTTPForbidden.code, description=description)


class Signin_POST_ConflictResponseSchema(BaseResponseSchemaAPI):
    description = "Add external user identity refused by db because it already exists."
    body = ErrorResponseBodySchema(code=HTTPConflict.code, description=description)


class Signin_POST_InternalServerErrorBodySchema(InternalServerErrorResponseBodySchema):
    user_name = colander.SchemaNode(colander.String(), description="Specified user retrieved from the request.")
    provider_name = colander.SchemaNode(colander.String(), description="Specified provider retrieved from the request.")


class Signin_POST_Internal_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Unknown login error."
    body = Signin_POST_InternalServerErrorBodySchema(code=HTTPInternalServerError.code, description=description)


class Signin_POST_External_InternalServerErrorResponseSchema(BaseResponseSchemaAPI):
    description = "Error occurred while signing in with external provider."
    body = Signin_POST_InternalServerErrorBodySchema(code=HTTPInternalServerError.code, description=description)


class Signout_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Sign out successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class Version_GET_ResponseBodySchema(BaseResponseBodySchema):
    version = colander.SchemaNode(
        colander.String(),
        description="Magpie version string",
        example=__meta__.__version__)
    db_version = colander.SchemaNode(
        colander.String(),
        description="Database version string",
        exemple="a395ef9d3fe6")


class Version_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get version successful."
    body = Version_GET_ResponseBodySchema(code=HTTPOk.code, description=description)


class Homepage_GET_OkResponseSchema(BaseResponseSchemaAPI):
    description = "Get homepage successful."
    body = BaseResponseBodySchema(code=HTTPOk.code, description=description)


class SwaggerAPI_GET_OkResponseSchema(colander.MappingSchema):
    description = TitleAPI
    header = RequestHeaderSchemaUI()
    body = colander.SchemaNode(colander.String(), example="This page!")


# Responses for specific views
Resource_GET_responses = {
    "200": Resource_GET_OkResponseSchema(),
    "400": Resource_MatchDictCheck_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Resource_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Resource_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": Resource_GET_InternalServerErrorResponseSchema()
}
Resource_PATCH_responses = {
    "200": Resource_PATCH_OkResponseSchema(),
    "400": Resource_PATCH_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": Resource_PATCH_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Resource_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": Resource_PATCH_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Resources_GET_responses = {
    "200": Resources_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": Resource_GET_InternalServerErrorResponseSchema(),
}
Resources_POST_responses = {
    "201": Resources_POST_CreatedResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Resources_POST_ForbiddenResponseSchema(),
    "404": Resources_POST_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": Resources_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Resources_DELETE_responses = {
    "200": Resource_DELETE_OkResponseSchema(),
    "400": Resource_MatchDictCheck_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Resource_DELETE_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Resource_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ResourcePermissions_GET_responses = {
    "200": ResourcePermissions_GET_OkResponseSchema(),
    "400": ResourcePermissions_GET_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Resource_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Resource_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ServiceTypes_GET_responses = {
    "200": ServiceTypes_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ServiceType_GET_responses = {
    "200": Services_GET_OkResponseSchema(),
    "400": Services_GET_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Services_GET_responses = {
    "200": Services_GET_OkResponseSchema(),
    "400": Services_GET_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Services_POST_responses = {
    "201": Services_POST_CreatedResponseSchema(),
    "400": Services_POST_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Services_POST_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "406": NotAcceptableResponseSchema(),
    "409": Services_POST_ConflictResponseSchema(),
    "422": Services_POST_UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Service_GET_responses = {
    "200": Service_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Service_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Service_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Service_PATCH_responses = {
    "200": Service_PATCH_OkResponseSchema(),
    "400": Service_PATCH_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Service_PATCH_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "406": NotAcceptableResponseSchema(),
    "409": Service_PATCH_ConflictResponseSchema(),
    "422": Service_CheckConfig_UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Service_DELETE_responses = {
    "200": Service_DELETE_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Service_DELETE_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Service_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ServicePermissions_GET_responses = {
    "200": ServicePermissions_GET_OkResponseSchema(),
    "400": ServicePermissions_GET_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Service_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Service_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ServiceResources_GET_responses = {
    "200": ServiceResources_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Service_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Service_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ServiceResources_POST_responses = {
    "201": ServiceResources_POST_CreatedResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": ServiceResources_POST_ForbiddenResponseSchema(),
    "404": ServiceResources_POST_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": ServiceResources_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ServiceTypeResources_GET_responses = {
    "200": ServiceTypeResources_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": ServiceTypeResources_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": ServiceTypeResources_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ServiceTypeResourceTypes_GET_responses = {
    "200": ServiceTypeResourceTypes_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": ServiceTypeResourceTypes_GET_ForbiddenResponseSchema(),
    "404": ServiceTypeResourceTypes_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ServiceResource_DELETE_responses = {
    "200": ServiceResource_DELETE_OkResponseSchema(),
    "400": Resource_MatchDictCheck_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": ServiceResource_DELETE_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Resource_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Users_GET_responses = {
    "200": Users_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Users_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Users_POST_responses = {
    "201": Users_POST_CreatedResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Users_POST_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "406": NotAcceptableResponseSchema(),
    "409": User_Check_ConflictResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
User_GET_responses = {
    "200": User_GET_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
User_PATCH_responses = {
    "200": Users_PATCH_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": UserGroup_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "406": NotAcceptableResponseSchema(),
    "409": User_Check_ConflictResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
User_DELETE_responses = {
    "200": User_DELETE_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserResources_GET_responses = {
    "200": UserResources_GET_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": UserResources_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserGroups_GET_responses = {
    "200": UserGroups_GET_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserGroups_POST_responses = {
    "201": UserGroups_POST_CreatedResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": UserGroups_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserGroup_DELETE_responses = {
    "200": UserGroup_DELETE_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": UserGroup_DELETE_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": UserGroup_DELETE_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserResourcePermissions_GET_responses = {
    "200": UserResourcePermissions_GET_OkResponseSchema(),
    "400": Resource_MatchDictCheck_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": Resource_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Resource_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserResourcePermissions_POST_responses = {
    "201": UserResourcePermissions_POST_CreatedResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "400": UserResourcePermissions_POST_BadRequestResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": UserResourcePermissions_POST_ForbiddenResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": UserResourcePermissions_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
# same method handles operations/results/messages, but conflict will not occur
UserResourcePermissions_PUT_responses = {
    "200": UserResourcePermissions_PUT_OkResponseSchema(),          # updated
    "201": UserResourcePermissions_PUT_CreatedResponseSchema(),     # created
    "401": UnauthorizedResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": UserResourcePermissions_PUT_ForbiddenResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    # 409: not applicable
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserResourcePermissions_DELETE_responses = {
    "200": UserResourcePermissions_DELETE_OkResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "400": UserResourcePermissions_DELETE_BadRequestResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "404": UserResourcePermissions_DELETE_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserResourcePermissionName_DELETE_responses = {
    "200": UserResourcePermissionName_DELETE_OkResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "400": UserResourcePermissionName_DELETE_BadRequestResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "404": UserResourcePermissionName_DELETE_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserServices_GET_responses = {
    "200": UserServices_GET_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": User_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": User_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserServicePermissions_GET_responses = {
    "200": UserServicePermissions_GET_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": User_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": UserServicePermissions_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserServiceResources_GET_responses = {
    "200": UserServiceResources_GET_OkResponseSchema(),
    "400": User_Check_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": User_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Service_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
UserServicePermissions_POST_responses = UserResourcePermissions_POST_responses
UserServicePermissions_PUT_responses = UserResourcePermissions_PUT_responses
UserServicePermissions_DELETE_responses = UserResourcePermissions_DELETE_responses
UserServicePermissionName_DELETE_responses = UserResourcePermissionName_DELETE_responses
LoggedUser_GET_responses = {
    "200": User_GET_OkResponseSchema(),
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUser_PATCH_responses = {
    "200": Users_PATCH_OkResponseSchema(),
    "400": User_PATCH_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": User_PATCH_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "406": NotAcceptableResponseSchema(),
    "409": User_PATCH_ConflictResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUser_DELETE_responses = {
    "200": User_DELETE_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserResources_GET_responses = {
    "200": UserResources_GET_OkResponseSchema(),
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": UserResources_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserGroups_GET_responses = {
    "200": UserGroups_GET_OkResponseSchema(),
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserGroups_POST_responses = {
    "201": UserGroups_POST_CreatedResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": UserGroups_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserGroup_DELETE_responses = {
    "200": UserGroup_DELETE_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": User_CheckAnonymous_ForbiddenResponseSchema(),
    "404": User_CheckAnonymous_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserResourcePermissions_GET_responses = {
    "200": UserResourcePermissions_GET_OkResponseSchema(),
    "400": Resource_MatchDictCheck_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": Resource_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Resource_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserResourcePermissions_POST_responses = {
    "201": UserResourcePermissions_POST_CreatedResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "400": UserResourcePermissions_POST_BadRequestResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": UserResourcePermissions_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
# same method handles operations/results/messages, but conflict will not occur
LoggedUserResourcePermissions_PUT_responses = {
    "200": UserResourcePermissions_PUT_OkResponseSchema(),          # updated
    "201": UserResourcePermissions_PUT_CreatedResponseSchema(),     # created
    "401": UnauthorizedResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    # 409: not applicable
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserResourcePermissions_DELETE_responses = {
    "200": UserResourcePermissions_DELETE_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "404": UserResourcePermissions_DELETE_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserResourcePermissionName_DELETE_responses = {
    "200": UserResourcePermissionName_DELETE_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "404": UserResourcePermissionName_DELETE_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserServices_GET_responses = {
    "200": UserServices_GET_OkResponseSchema(),
    "403": User_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": User_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserServicePermissions_GET_responses = {
    "200": UserServicePermissions_GET_OkResponseSchema(),
    "403": User_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": UserServicePermissions_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserServiceResources_GET_responses = {
    "200": UserServiceResources_GET_OkResponseSchema(),
    "403": User_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Service_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
LoggedUserServicePermissions_POST_responses = LoggedUserResourcePermissions_POST_responses
LoggedUserServicePermissions_PUT_responses = LoggedUserResourcePermissions_PUT_responses
LoggedUserServicePermissions_DELETE_responses = LoggedUserResourcePermissions_DELETE_responses
LoggedUserServicePermissionName_DELETE_responses = LoggedUserResourcePermissionName_DELETE_responses
Groups_GET_responses = {
    "200": Groups_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Groups_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Groups_POST_responses = {
    "201": Groups_POST_CreatedResponseSchema(),
    "400": Groups_POST_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Groups_POST_ForbiddenCreateResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "406": NotAcceptableResponseSchema(),
    "409": Groups_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Group_GET_responses = {
    "200": Group_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Group_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Group_PATCH_responses = {
    "200": Group_PATCH_OkResponseSchema(),
    "400": Group_PATCH_Name_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": UnauthorizedResponseSchema(),
    "403": Group_PATCH_ReservedKeyword_ForbiddenResponseSchema(),
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": Group_PATCH_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Group_DELETE_responses = {
    "200": Group_DELETE_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Group_DELETE_ReservedKeyword_ForbiddenResponseSchema(),
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
GroupUsers_GET_responses = {
    "200": GroupUsers_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": GroupUsers_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
GroupServices_GET_responses = {
    "200": GroupServices_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": GroupServices_InternalServerErrorResponseSchema(),
}
GroupServicePermissions_GET_responses = {
    "200": GroupServicePermissions_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Group_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": GroupServicePermissions_GET_InternalServerErrorResponseSchema(),
}
GroupServiceResources_GET_responses = {
    "200": GroupServiceResources_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Group_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
GroupResourcePermissions_POST_responses = {
    "201": GroupResourcePermissions_POST_CreatedResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": GroupResourcePermissions_POST_ForbiddenGetResponseSchema(),
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": GroupResourcePermissions_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
GroupServicePermissions_POST_responses = GroupResourcePermissions_POST_responses
GroupResourcePermissions_PUT_responses = {
    "200": GroupResourcePermissions_PUT_OkResponseSchema(),         # updated
    "201": GroupResourcePermissions_PUT_CreatedResponseSchema(),    # created
    "401": UnauthorizedResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": GroupResourcePermissions_PUT_ForbiddenResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    # 409: not applicable
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
GroupServicePermissions_PUT_responses = GroupResourcePermissions_PUT_responses
GroupServicePermissionName_DELETE_responses = {
    "200": GroupServicePermission_DELETE_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "403": GroupServicePermission_DELETE_ForbiddenResponseSchema(),
    "404": GroupServicePermission_DELETE_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
GroupServicePermissions_DELETE_responses = GroupServicePermissionName_DELETE_responses
GroupResourcePermissions_DELETE_responses = GroupServicePermissions_DELETE_responses
GroupResourcePermissionName_DELETE_responses = GroupServicePermissionName_DELETE_responses
GroupResources_GET_responses = {
    "200": GroupResources_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Group_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": GroupResources_GET_InternalServerErrorResponseSchema(),
}
GroupResourcePermissions_GET_responses = {
    "200": GroupResourcePermissions_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": Group_MatchDictCheck_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": Group_MatchDictCheck_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
RegisterGroups_GET_responses = {
    "200": RegisterGroups_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": RegisterGroups_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "500": InternalServerErrorResponseSchema(),
}
RegisterGroup_GET_responses = {
    "200": RegisterGroup_GET_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "404": RegisterGroup_NotFoundResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
RegisterGroup_POST_responses = {
    "201": RegisterGroup_POST_CreatedResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": RegisterGroup_POST_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": RegisterGroup_NotFoundResponseSchema(),
    "409": RegisterGroup_POST_ConflictResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
RegisterGroup_DELETE_responses = {
    "200": RegisterGroup_DELETE_OkResponseSchema(),
    "401": UnauthorizedResponseSchema(),
    "403": RegisterGroup_DELETE_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": RegisterGroup_DELETE_NotFoundResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
TemporaryURL_GET_responses = {
    "200": TemporaryURL_GET_OkResponseSchema(),
    "404": TemporaryURL_GET_NotFoundResponseSchema(),
    "410": TemporaryURL_GET_GoneResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Providers_GET_responses = {
    "200": Providers_GET_OkResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
ProviderSignin_GET_responses = {
    "302": ProviderSignin_GET_FoundResponseSchema(),
    "400": ProviderSignin_GET_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": ProviderSignin_GET_UnauthorizedResponseSchema(),
    "403": ProviderSignin_GET_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": ProviderSignin_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Signin_POST_responses = {
    "200": Signin_POST_OkResponseSchema(),
    "400": Signin_POST_BadRequestResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "401": Signin_POST_UnauthorizedResponseSchema(),
    "403": Signin_POST_ForbiddenResponseSchema(),  # FIXME: https://github.com/Ouranosinc/Magpie/issues/359
    "404": ProviderSignin_GET_NotFoundResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "409": Signin_POST_ConflictResponseSchema(),
    "422": UnprocessableEntityResponseSchema(),
    "500": Signin_POST_Internal_InternalServerErrorResponseSchema(),
}
Signin_GET_responses = Signin_POST_responses
Signout_GET_responses = {
    "200": Signout_GET_OkResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Session_GET_responses = {
    "200": Session_GET_OkResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": Session_GET_InternalServerErrorResponseSchema(),
}
Version_GET_responses = {
    "200": Version_GET_OkResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
Homepage_GET_responses = {
    "200": Homepage_GET_OkResponseSchema(),
    "406": NotAcceptableResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}
SwaggerAPI_GET_responses = {
    "200": SwaggerAPI_GET_OkResponseSchema(),
    "500": InternalServerErrorResponseSchema(),
}


def generate_api_schema(swagger_base_spec):
    # type: (Dict[Str, Union[Str, List[Str]]]) -> JSON
    """
    Return JSON Swagger specifications of Magpie REST API.

    Uses Cornice Services and Schemas to return swagger specification.

    :param swagger_base_spec: dictionary that specifies the 'host' and list of HTTP 'schemes' to employ.
    """
    generator = CorniceSwagger(get_services())
    # function docstrings are used to create the route's summary in Swagger-UI
    generator.summary_docstrings = True
    generator.default_security = get_security
    swagger_base_spec.update(SecurityDefinitionsAPI)
    generator.swagger = swagger_base_spec
    json_api_spec = generator.generate(title=TitleAPI, version=__meta__.__version__, info=InfoAPI)
    for tag in json_api_spec["tags"]:
        tag["description"] = TAG_DESCRIPTIONS[tag["name"]]
    return json_api_spec
