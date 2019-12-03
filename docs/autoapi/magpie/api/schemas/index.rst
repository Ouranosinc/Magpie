:mod:`magpie.api.schemas`
=========================

.. py:module:: magpie.api.schemas


Module Contents
---------------

.. data:: TitleAPI
   :annotation: = Magpie REST API

   

.. data:: InfoAPI
   

   

.. data:: APITag
   :annotation: = API

   

.. data:: LoginTag
   :annotation: = Login

   

.. data:: UsersTag
   :annotation: = User

   

.. data:: LoggedUserTag
   :annotation: = Logged User

   

.. data:: GroupsTag
   :annotation: = Group

   

.. data:: ResourcesTag
   :annotation: = Resource

   

.. data:: ServicesTag
   :annotation: = Service

   

.. data:: SecurityCookieAuthAPI
   

   

.. data:: SecurityDefinitionsAPI
   

   

.. data:: SecurityAdministratorAPI
   

   

.. data:: SecurityEveryoneAPI
   

   

.. function:: get_security(service, method)

.. function:: service_api_route_info(service_api)

.. data:: LoggedUserBase
   

   

.. data:: SwaggerGenerator
   

   

.. data:: SwaggerAPI
   

   

.. data:: UsersAPI
   

   

.. data:: UserAPI
   

   

.. data:: UserGroupsAPI
   

   

.. data:: UserGroupAPI
   

   

.. data:: UserInheritedResourcesAPI
   

   

.. data:: UserResourcesAPI
   

   

.. data:: UserResourceInheritedPermissionsAPI
   

   

.. data:: UserResourcePermissionAPI
   

   

.. data:: UserResourcePermissionsAPI
   

   

.. data:: UserResourceTypesAPI
   

   

.. data:: UserInheritedServicesAPI
   

   

.. data:: UserServicesAPI
   

   

.. data:: UserServiceAPI
   

   

.. data:: UserServiceInheritedResourcesAPI
   

   

.. data:: UserServiceResourcesAPI
   

   

.. data:: UserServiceInheritedPermissionsAPI
   

   

.. data:: UserServicePermissionsAPI
   

   

.. data:: UserServicePermissionAPI
   

   

.. data:: LoggedUserAPI
   

   

.. data:: LoggedUserGroupsAPI
   

   

.. data:: LoggedUserGroupAPI
   

   

.. data:: LoggedUserInheritedResourcesAPI
   

   

.. data:: LoggedUserResourcesAPI
   

   

.. data:: LoggedUserResourceInheritedPermissionsAPI
   

   

.. data:: LoggedUserResourcePermissionAPI
   

   

.. data:: LoggedUserResourcePermissionsAPI
   

   

.. data:: LoggedUserResourceTypesAPI
   

   

.. data:: LoggedUserInheritedServicesAPI
   

   

.. data:: LoggedUserServicesAPI
   

   

.. data:: LoggedUserServiceInheritedResourcesAPI
   

   

.. data:: LoggedUserServiceResourcesAPI
   

   

.. data:: LoggedUserServiceInheritedPermissionsAPI
   

   

.. data:: LoggedUserServicePermissionsAPI
   

   

.. data:: LoggedUserServicePermissionAPI
   

   

.. data:: GroupsAPI
   

   

.. data:: GroupAPI
   

   

.. data:: GroupUsersAPI
   

   

.. data:: GroupServicesAPI
   

   

.. data:: GroupServicePermissionsAPI
   

   

.. data:: GroupServicePermissionAPI
   

   

.. data:: GroupServiceResourcesAPI
   

   

.. data:: GroupResourcesAPI
   

   

.. data:: GroupResourcePermissionsAPI
   

   

.. data:: GroupResourcePermissionAPI
   

   

.. data:: GroupResourceTypesAPI
   

   

.. data:: ResourcesAPI
   

   

.. data:: ResourceAPI
   

   

.. data:: ResourcePermissionsAPI
   

   

.. data:: ServicesAPI
   

   

.. data:: ServiceAPI
   

   

.. data:: ServiceTypesAPI
   

   

.. data:: ServiceTypeAPI
   

   

.. data:: ServicePermissionsAPI
   

   

.. data:: ServiceResourcesAPI
   

   

.. data:: ServiceResourceAPI
   

   

.. data:: ServiceTypeResourcesAPI
   

   

.. data:: ServiceTypeResourceTypesAPI
   

   

.. data:: ProvidersAPI
   

   

.. data:: ProviderSigninAPI
   

   

.. data:: SigninAPI
   

   

.. data:: SignoutAPI
   

   

.. data:: SessionAPI
   

   

.. data:: VersionAPI
   

   

.. data:: HomepageAPI
   

   

.. data:: GroupNameParameter
   

   

.. data:: UserNameParameter
   

   

.. data:: ProviderNameParameter
   

   

.. data:: PermissionNameParameter
   

   

.. data:: ResourceIdParameter
   

   

.. data:: ServiceNameParameter
   

   

.. py:class:: HeaderResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: content_type
      

      

   .. attribute:: name
      :annotation: = Content-Type

      


.. py:class:: HeaderRequestSchemaAPI

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: content_type
      

      

   .. attribute:: name
      :annotation: = Content-Type

      


.. py:class:: HeaderRequestSchemaUI

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: content_type
      

      

   .. attribute:: name
      :annotation: = Content-Type

      


.. data:: QueryEffectivePermissions
   

   

.. data:: QueryInheritGroupsPermissions
   

   

.. data:: QueryCascadeResourcesPermissions
   

   

.. py:class:: BaseResponseBodySchema(code, description, **kw)

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`


.. py:class:: ErrorVerifyParamBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: name
      

      

   .. attribute:: value
      

      

   .. attribute:: compare
      

      


.. py:class:: ErrorResponseBodySchema(code, description, **kw)

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: route_name
      

      

   .. attribute:: request_url
      

      

   .. attribute:: method
      

      


.. py:class:: InternalServerErrorResponseBodySchema(**kw)

   Bases: :class:`magpie.api.schemas.ErrorResponseBodySchema`


.. py:class:: UnauthorizedResponseBodySchema(**kw)

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: route_name
      

      

   .. attribute:: request_url
      

      


.. py:class:: UnauthorizedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: HTTPForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Forbidden operation under this resource.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = The route resource could not be found.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: MethodNotAllowedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = The method is not allowed for this resource.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: NotAcceptableResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Unsupported 'Accept Header' was specified.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UnprocessableEntityResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid value specified.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Internal Server Error. Unhandled exception occurred.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ProvidersListSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.SequenceSchema`

   .. attribute:: provider_name
      

      


.. py:class:: ResourceTypesListSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.SequenceSchema`

   .. attribute:: resource_type
      

      


.. py:class:: GroupNamesListSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.SequenceSchema`

   .. attribute:: group_name
      

      


.. py:class:: UserNamesListSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.SequenceSchema`

   .. attribute:: user_name
      

      


.. py:class:: PermissionListSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.SequenceSchema`

   .. attribute:: permission_name
      

      


.. py:class:: UserBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: user_name
      

      

   .. attribute:: email
      

      

   .. attribute:: group_names
      

      


.. py:class:: GroupBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: group_name
      

      

   .. attribute:: group_id
      

      


.. py:class:: GroupDetailBodySchema

   Bases: :class:`magpie.api.schemas.GroupBodySchema`

   .. attribute:: description
      

      

   .. attribute:: member_count
      

      

   .. attribute:: user_names
      

      


.. py:class:: ServiceBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: resource_id
      

      

   .. attribute:: permission_names
      

      

   .. attribute:: service_name
      

      

   .. attribute:: service_type
      

      

   .. attribute:: service_sync_type
      

      

   .. attribute:: public_url
      

      

   .. attribute:: service_url
      

      


.. py:class:: ResourceBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: resource_id
      

      

   .. attribute:: resource_name
      

      

   .. attribute:: resource_display_name
      

      

   .. attribute:: resource_type
      

      

   .. attribute:: parent_id
      

      

   .. attribute:: root_service_id
      

      

   .. attribute:: permission_names
      

      

   .. attribute:: default
      

      

   .. attribute:: missing
      

      


.. py:class:: Resource_ChildrenContainerWithoutChildResourceBodySchema

   Bases: :class:`magpie.api.schemas.ResourceBodySchema`

   .. attribute:: children
      

      


.. py:class:: Resource_ChildResourceWithoutChildrenBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: id
      

      

   .. attribute:: name
      :annotation: = {resource_id}

      


.. py:class:: Resource_ParentResourceWithChildrenContainerBodySchema

   Bases: :class:`magpie.api.schemas.ResourceBodySchema`

   .. attribute:: children
      

      


.. py:class:: Resource_ChildrenContainerWithChildResourceBodySchema

   Bases: :class:`magpie.api.schemas.ResourceBodySchema`

   .. attribute:: children
      

      


.. py:class:: Resource_ChildResourceWithChildrenContainerBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: id
      

      

   .. attribute:: name
      :annotation: = {resource_id}

      


.. py:class:: Resource_ServiceWithChildrenResourcesContainerBodySchema

   Bases: :class:`magpie.api.schemas.ServiceBodySchema`

   .. attribute:: resources
      

      


.. py:class:: Resource_ServiceType_geoserverapi_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: geoserver_api
      

      

   .. attribute:: name
      :annotation: = geoserver-api

      


.. py:class:: Resource_ServiceType_ncwms_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: ncwms
      

      


.. py:class:: Resource_ServiceType_thredds_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: thredds
      

      


.. py:class:: ResourcesSchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: geoserver_api
      

      

   .. attribute:: name
      :annotation: = geoserver-api

      

   .. attribute:: ncwms
      

      

   .. attribute:: thredds
      

      


.. py:class:: Resources_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resources
      

      


.. py:class:: Resource_MatchDictCheck_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Resource query by id refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_MatchDictCheck_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Resource ID not found in db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_MatchDictCheck_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Resource ID is an invalid literal for 'int' type.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resource
      

      


.. py:class:: Resource_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get resource successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_GET_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed building resource children json formatted tree.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_PUT_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: resource_name
      

      

   .. attribute:: service_push
      

      


.. py:class:: Resource_PUT_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: resource_id
      

      


.. py:class:: Resource_PUT_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resource_id
      

      

   .. attribute:: resource_name
      

      

   .. attribute:: old_resource_name
      

      

   .. attribute:: new_resource_name
      

      


.. py:class:: Resource_PUT_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Update resource successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_PUT_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to update resource with new name.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_DELETE_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: service_push
      

      


.. py:class:: Resource_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: resource_id
      

      


.. py:class:: Resource_DELETE_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete resource successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_DELETE_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete resource from db failed.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resources_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get resources successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resources_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: resource_name
      

      

   .. attribute:: resource_display_name
      

      

   .. attribute:: resource_type
      

      

   .. attribute:: parent_id
      

      


.. py:class:: Resources_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resource_POST_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resource
      

      


.. py:class:: Resources_POST_CreatedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Create resource successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resources_POST_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid ['resource_name'|'resource_type'|'parent_id'] specified for child resource creation.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resources_POST_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to insert new resource in service tree using parent id.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resources_POST_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Could not find specified resource parent id.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Resources_POST_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Resource name already exists at requested tree level for creation.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ResourcePermissions_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: permission_names
      

      


.. py:class:: ResourcePermissions_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get resource permissions successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ResourcePermissions_GET_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid resource type to extract permissions.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServiceResourcesBodySchema

   Bases: :class:`magpie.api.schemas.ServiceBodySchema`

   .. attribute:: children
      

      


.. py:class:: ServiceType_access_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: frontend
      

      

   .. attribute:: geoserver_web
      

      

   .. attribute:: name
      :annotation: = geoserver-web

      

   .. attribute:: magpie
      

      


.. py:class:: ServiceType_geoserverapi_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: geoserver_api
      

      

   .. attribute:: name
      :annotation: = geoserver-api

      


.. py:class:: ServiceType_geoserverwms_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: geoserverwms
      

      


.. py:class:: ServiceType_ncwms_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: ncwms
      

      

   .. attribute:: name
      :annotation: = ncWMS2

      


.. py:class:: ServiceType_projectapi_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: project_api
      

      

   .. attribute:: name
      :annotation: = project-api

      


.. py:class:: ServiceType_thredds_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: thredds
      

      


.. py:class:: ServiceType_wfs_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: geoserver
      

      


.. py:class:: ServiceType_wps_SchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: lb_flyingpigeon
      

      

   .. attribute:: flyingpigeon
      

      

   .. attribute:: project
      

      

   .. attribute:: catalog
      

      

   .. attribute:: malleefowl
      

      

   .. attribute:: hummingbird
      

      


.. py:class:: ServiceTypesList

   Bases: :class:`magpie.definitions.cornice_definitions.colander.SequenceSchema`

   .. attribute:: service_type
      

      


.. py:class:: ServiceTypes_GET_OkResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service_types
      

      


.. py:class:: ServiceTypes_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get service types successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServicesSchemaNode

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: access
      

      

   .. attribute:: geoserver_api
      

      

   .. attribute:: name
      :annotation: = geoserver-api

      

   .. attribute:: geoserverwms
      

      

   .. attribute:: ncwms
      

      

   .. attribute:: project_api
      

      

   .. attribute:: name
      :annotation: = project-api

      

   .. attribute:: thredds
      

      

   .. attribute:: wfs
      

      

   .. attribute:: wps
      

      


.. py:class:: Service_FailureBodyResponseSchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service_name
      

      


.. py:class:: Service_MatchDictCheck_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Service query by name refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_MatchDictCheck_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Service name not found in db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service
      

      


.. py:class:: Service_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get service successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: services
      

      


.. py:class:: Services_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get services successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_GET_BadRequestResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service_type
      

      


.. py:class:: Services_GET_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'service_type' value does not correspond to any of the existing service types.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_POST_BodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: service_name
      

      

   .. attribute:: service_type
      

      

   .. attribute:: service_sync_type
      

      

   .. attribute:: service_url
      

      


.. py:class:: Services_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_POST_CreatedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Service registration to db successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_POST_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'service_type' value does not correspond to any of the existing service types.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_POST_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Service registration forbidden by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_POST_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Specified 'service_name' value already exists.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_POST_UnprocessableEntityResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Service creation for registration failed.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Services_POST_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Service registration status could not be validated.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_PUT_ResponseBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: service_name
      

      

   .. attribute:: service_url
      

      

   .. attribute:: service_push
      

      


.. py:class:: Service_PUT_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_SuccessBodyResponseSchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service
      

      


.. py:class:: Service_PUT_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Update service successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_PUT_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Registered service values are already equal to update values.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_PUT_BadRequestResponseSchema_ReservedKeyword

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Update service name to 'types' not allowed (reserved keyword).

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_PUT_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Update service failed during value assignment.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_PUT_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Specified 'service_name' already exists.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: service_name
      

      


.. py:class:: Service_DELETE_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete service successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Service_DELETE_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete service from db refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServicePermissions_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: permission_names
      

      


.. py:class:: ServicePermissions_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get service permissions successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServicePermissions_GET_BadRequestResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service
      

      


.. py:class:: ServicePermissions_GET_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid service type specified by service.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServiceResources_POST_RequestSchema

   Bases: :class:`magpie.api.schemas.Resources_POST_RequestSchema`

   .. attribute:: service_name
      

      


.. data:: ServiceResources_POST_CreatedResponseSchema
   

   

.. data:: ServiceResources_POST_BadRequestResponseSchema
   

   

.. data:: ServiceResources_POST_ForbiddenResponseSchema
   

   

.. data:: ServiceResources_POST_NotFoundResponseSchema
   

   

.. data:: ServiceResources_POST_ConflictResponseSchema
   

   

.. py:class:: ServiceResource_DELETE_RequestSchema

   Bases: :class:`magpie.api.schemas.Resource_DELETE_RequestSchema`

   .. attribute:: service_name
      

      


.. data:: ServiceResource_DELETE_ForbiddenResponseSchema
   

   

.. data:: ServiceResource_DELETE_OkResponseSchema
   

   

.. py:class:: ServiceResources_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service_name
      

      

   .. attribute:: name
      :annotation: = {service_name}

      


.. py:class:: ServiceResources_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get service resources successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServiceTypeResourceTypes_GET_FailureBodyResponseSchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service_type
      

      


.. py:class:: ServiceTypeResourceInfo

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: resource_type
      

      

   .. attribute:: resource_child_allowed
      

      

   .. attribute:: permission_names
      

      


.. py:class:: ServiceTypeResourcesList

   Bases: :class:`magpie.definitions.cornice_definitions.colander.SequenceSchema`

   .. attribute:: resource_type
      

      


.. py:class:: ServiceTypeResources_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resource_types
      

      


.. py:class:: ServiceTypeResources_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get service type resources successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServiceTypeResources_GET_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to obtain resource types for specified service type.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServiceTypeResources_GET_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'service_type' does not exist to obtain its resource types.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServiceTypeResourceTypes_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resource_types
      

      


.. py:class:: ServiceTypeResourceTypes_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get service type resource types successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServiceTypeResourceTypes_GET_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to obtain resource types for specified service type.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ServiceTypeResourceTypes_GET_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'service_type' does not exist to obtain its resource types.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: user_names
      

      


.. py:class:: Users_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get users successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_GET_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get users query refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_CheckInfo_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: param
      

      


.. py:class:: Users_CheckInfo_Name_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'user_name' value specified.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_CheckInfo_Size_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_CheckInfo_Email_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'email' value specified.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_CheckInfo_Password_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'password' value specified.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_CheckInfo_GroupName_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'group_name' value specified.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_CheckInfo_ReservedKeyword_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'user_name' not allowed (reserved keyword).

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_Check_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = User check query was refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_Check_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = User name matches an already existing user name.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: user_name
      

      

   .. attribute:: email
      

      

   .. attribute:: password
      

      

   .. attribute:: group_name
      

      


.. py:class:: Users_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_POST_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: user
      

      


.. py:class:: Users_POST_CreatedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Add user to db successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_POST_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to add user to db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserNew_POST_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = New user query was refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_PUT_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: user_name
      

      

   .. attribute:: email
      

      

   .. attribute:: password
      

      


.. py:class:: User_PUT_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Users_PUT_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Update user successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_PUT_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Missing new user parameters to update.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_PUT_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed user verification with db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_PUT_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = New name user already exists.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: user
      

      


.. py:class:: User_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get user successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_CheckAnonymous_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Anonymous user query refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_CheckAnonymous_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Anonymous user not found in db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_GET_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = User name query refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_GET_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = User name not found in db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_DELETE_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete user successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: User_DELETE_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete user by name refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroup_Check_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group for new user doesn't exist.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroup_GET_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group query was refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroup_Check_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to add user-group to db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroups_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: group_names
      

      


.. py:class:: UserGroups_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get user groups successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroups_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: user_name
      

      

   .. attribute:: group_name
      

      


.. py:class:: UserGroups_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: user_name
      

      


.. py:class:: UserGroups_POST_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: user_name
      

      

   .. attribute:: group_name
      

      


.. py:class:: UserGroups_POST_CreatedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Create user-group assignation successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroups_POST_GroupNotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Can't find the group to assign to.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroups_POST_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group query by name refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroups_POST_RelationshipForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = User-Group relationship creation refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroups_POST_ConflictResponseBodySchema

   Bases: :class:`magpie.api.schemas.ErrorResponseBodySchema`

   .. attribute:: param
      

      

   .. attribute:: user_name
      

      

   .. attribute:: group_name
      

      


.. py:class:: UserGroups_POST_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = User already belongs to this group.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroup_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroup_DELETE_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete user-group successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserGroup_DELETE_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid user-group combination for delete.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResources_GET_QuerySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: inherit
      

      


.. py:class:: UserResources_GET_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: querystring
      

      


.. py:class:: UserResources_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resources
      

      


.. py:class:: UserResources_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get user resources successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResources_GET_NotFoundResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: user_name
      

      

   .. attribute:: resource_types
      

      


.. py:class:: UserResources_GET_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to populate user resources.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_GET_QuerySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: inherit
      

      

   .. attribute:: effective
      

      


.. py:class:: UserResourcePermissions_GET_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: querystring
      

      


.. py:class:: UserResourcePermissions_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: permission_names
      

      


.. py:class:: UserResourcePermissions_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get user resource permissions successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_GET_BadRequestParamResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: name
      

      

   .. attribute:: value
      

      

   .. attribute:: compare
      

      


.. py:class:: UserResourcePermissions_GET_BadRequestResponseBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: param
      

      


.. py:class:: UserResourcePermissions_GET_BadRequestRootServiceResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'resource' specified for resource permission retrieval.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_GET_BadRequestResourceResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'resource' specified for resource permission retrieval.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_GET_BadRequestResourceTypeResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'resource_type' for corresponding service resource permission retrieval.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_GET_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Specified user not found to obtain resource permissions.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: permission_name
      

      


.. py:class:: UserResourcePermissions_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: resource_id
      

      

   .. attribute:: user_name
      

      


.. py:class:: UserResourcePermissions_POST_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resource_id
      

      

   .. attribute:: user_id
      

      

   .. attribute:: permission_name
      

      


.. py:class:: UserResourcePermissions_POST_CreatedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Create user resource permission successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_POST_ParamResponseBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: name
      

      

   .. attribute:: value
      

      


.. py:class:: UserResourcePermissions_POST_BadResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: user_name
      

      

   .. attribute:: resource_id
      

      

   .. attribute:: permission_name
      

      

   .. attribute:: param
      

      


.. py:class:: UserResourcePermissions_POST_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Permission not allowed for specified 'resource_type'.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_POST_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Creation of permission on resource for user refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_POST_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Permission already exist on resource for user.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. data:: UserResourcePermissions_DELETE_BadResponseBodySchema
   

   

.. data:: UserResourcePermissions_DELETE_BadRequestResponseSchema
   

   

.. py:class:: UserResourcePermission_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: user_name
      

      

   .. attribute:: resource_id
      

      

   .. attribute:: permission_name
      

      


.. py:class:: UserResourcePermissions_DELETE_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete user resource permission successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserResourcePermissions_DELETE_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Could not find user resource permission to delete from db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserServiceResources_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service
      

      


.. py:class:: UserServiceResources_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get user service resources successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserServiceResources_GET_QuerySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: inherit
      

      


.. py:class:: UserServiceResources_GET_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: querystring
      

      

   .. attribute:: user_name
      

      

   .. attribute:: service_name
      

      


.. py:class:: UserServicePermissions_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: permission_name
      

      


.. py:class:: UserServicePermissions_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: user_name
      

      

   .. attribute:: service_name
      

      


.. py:class:: UserServicePermission_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: user_name
      

      

   .. attribute:: service_name
      

      

   .. attribute:: permission_name
      

      


.. py:class:: UserServices_GET_QuerySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: cascade
      

      

   .. attribute:: inherit
      

      

   .. attribute:: list
      

      


.. py:class:: UserServices_GET_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: querystring
      

      

   .. attribute:: user_name
      

      


.. py:class:: UserServices_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: services
      

      


.. py:class:: UserServices_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get user services successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserServicePermissions_GET_QuerySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: inherit
      

      


.. py:class:: UserServicePermissions_GET_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: querystring
      

      

   .. attribute:: user_name
      

      

   .. attribute:: service_name
      

      


.. py:class:: UserServicePermissions_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: permission_names
      

      


.. py:class:: UserServicePermissions_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get user service permissions successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: UserServicePermissions_GET_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Could not find permissions using specified 'service_name' and 'user_name'.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_MatchDictCheck_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group query by name refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_MatchDictCheck_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group name not found in db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_CheckInfo_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = User name not found in db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_CheckInfo_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to obtain groups of user.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: group_names
      

      


.. py:class:: Groups_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get groups successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_GET_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Obtain group names refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: group_name
      

      


.. py:class:: Groups_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_POST_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: group
      

      


.. py:class:: Groups_POST_CreatedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Create group successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_POST_ForbiddenCreateResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Create new group by name refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_POST_ForbiddenAddResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Add new group by name refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Groups_POST_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group name matches an already existing group name.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: group
      

      


.. py:class:: Group_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_GET_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group name was not found.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_PUT_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: group_name
      

      


.. py:class:: Group_PUT_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: group_name
      

      


.. py:class:: Group_PUT_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Update group successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_PUT_Name_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'group_name' value specified.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_PUT_Size_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_PUT_Same_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'group_name' must be different than current name.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_PUT_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group name already exists.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: group_name
      

      


.. py:class:: Group_DELETE_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete group successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Group_DELETE_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete group forbidden by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupUsers_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: user_names
      

      


.. py:class:: GroupUsers_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group users successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupUsers_GET_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to obtain group user names from db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServices_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: services
      

      


.. py:class:: GroupServices_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group services successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServices_InternalServerErrorResponseBodySchema

   Bases: :class:`magpie.api.schemas.InternalServerErrorResponseBodySchema`

   .. attribute:: group
      

      


.. py:class:: GroupServices_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to populate group services.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServicePermissions_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: permission_names
      

      


.. py:class:: GroupServicePermissions_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group service permissions successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServicePermissions_GET_InternalServerErrorResponseBodySchema

   Bases: :class:`magpie.api.schemas.InternalServerErrorResponseBodySchema`

   .. attribute:: group
      

      

   .. attribute:: service
      

      


.. py:class:: GroupServicePermissions_GET_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to extract permissions names from group-service.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServicePermissions_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: permission_name
      

      


.. py:class:: GroupServicePermissions_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: group_name
      

      

   .. attribute:: service_name
      

      


.. py:class:: GroupResourcePermissions_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: group_name
      

      

   .. attribute:: resource_id
      

      


.. py:class:: GroupResourcePermissions_POST_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: permission_name
      

      

   .. attribute:: resource
      

      

   .. attribute:: group
      

      


.. py:class:: GroupResourcePermissions_POST_CreatedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Create group resource permission successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResourcePermissions_POST_ForbiddenAddResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Add group resource permission refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResourcePermissions_POST_ForbiddenCreateResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Create group resource permission failed.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResourcePermissions_POST_ForbiddenGetResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group resource permission failed.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResourcePermissions_POST_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Group resource permission already exists.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResourcePermission_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: group_name
      

      

   .. attribute:: resource_id
      

      

   .. attribute:: permission_name
      

      


.. py:class:: GroupResourcesPermissions_InternalServerErrorResponseBodySchema

   Bases: :class:`magpie.api.schemas.InternalServerErrorResponseBodySchema`

   .. attribute:: group
      

      

   .. attribute:: resource_ids
      

      

   .. attribute:: resource_types
      

      


.. py:class:: GroupResourcesPermissions_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to build group resources json tree.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResourcePermissions_InternalServerErrorResponseBodySchema

   Bases: :class:`magpie.api.schemas.InternalServerErrorResponseBodySchema`

   .. attribute:: group
      

      

   .. attribute:: resource
      

      


.. py:class:: GroupResourcePermissions_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to obtain group resource permissions.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResources_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: resources
      

      


.. py:class:: GroupResources_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group resources successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResources_GET_InternalServerErrorResponseBodySchema

   Bases: :class:`magpie.api.schemas.InternalServerErrorResponseBodySchema`

   .. attribute:: group
      

      


.. py:class:: GroupResources_GET_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to build group resources json tree.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupResourcePermissions_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: permissions_names
      

      


.. py:class:: GroupResourcePermissions_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group resource permissions successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServiceResources_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: service
      

      


.. py:class:: GroupServiceResources_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group service resources successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServicePermission_DELETE_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: permission_name
      

      


.. py:class:: GroupServicePermission_DELETE_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      

   .. attribute:: group_name
      

      

   .. attribute:: service_name
      

      

   .. attribute:: permission_name
      

      


.. py:class:: GroupServicePermission_DELETE_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: permission_name
      

      

   .. attribute:: resource
      

      

   .. attribute:: group
      

      


.. py:class:: GroupServicePermission_DELETE_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete group resource permission successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServicePermission_DELETE_ForbiddenGetResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get group resource permission failed.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServicePermission_DELETE_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Delete group resource permission refused by db.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signout_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Sign out successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: GroupServicePermission_DELETE_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Permission not found for corresponding group and resource.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Session_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: user
      

      

   .. attribute:: authenticated
      

      


.. py:class:: Session_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get session successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Session_GET_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Failed to get session details.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ProvidersBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: internal
      

      

   .. attribute:: external
      

      


.. py:class:: Providers_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: providers
      

      


.. py:class:: Providers_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get providers successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ProviderSignin_GET_HeaderRequestSchema

   Bases: :class:`magpie.api.schemas.HeaderRequestSchemaAPI`

   .. attribute:: Authorization
      

      

   .. attribute:: HomepageRoute
      

      

   .. attribute:: name
      :annotation: = Homepage-Route

      


.. py:class:: ProviderSignin_GET_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: provider_name
      

      


.. py:class:: ProviderSignin_GET_FoundResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: homepage_route
      

      


.. py:class:: ProviderSignin_GET_FoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = External login homepage route found. Temporary status before redirection to 'Homepage-Route' header.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ProviderSignin_GET_BadRequestResponseBodySchema

   Bases: :class:`magpie.api.schemas.ErrorResponseBodySchema`

   .. attribute:: reason
      

      


.. py:class:: ProviderSignin_GET_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Incorrectly formed 'Authorization: Bearer <access_token>' header.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ProviderSignin_GET_UnauthorizedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Unauthorized 'UserInfo' update using provided Authorization headers.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ProviderSignin_GET_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Forbidden 'Homepage-Route' host not matching Magpie refused for security reasons.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: ProviderSignin_GET_NotFoundResponseBodySchema

   Bases: :class:`magpie.api.schemas.ErrorResponseBodySchema`

   .. attribute:: param
      

      

   .. attribute:: provider_name
      

      

   .. attribute:: providers
      

      


.. py:class:: ProviderSignin_GET_NotFoundResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Invalid 'provider_name' not found within available providers.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signin_POST_RequestBodySchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: user_name
      

      

   .. attribute:: password
      

      

   .. attribute:: provider_name
      

      


.. py:class:: Signin_POST_RequestSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signin_POST_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Login successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signin_POST_BadRequestResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Missing credentials.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signin_POST_UnauthorizedResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Incorrect credentials.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signin_POST_ForbiddenResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Could not verify 'user_name'.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signin_POST_ConflictResponseBodySchema

   Bases: :class:`magpie.api.schemas.ErrorResponseBodySchema`

   .. attribute:: provider_name
      

      

   .. attribute:: internal_user_name
      

      

   .. attribute:: external_user_name
      

      

   .. attribute:: external_id
      

      


.. py:class:: Signin_POST_ConflictResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Add external user identity refused by db because it already exists.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signin_POST_InternalServerErrorBodySchema

   Bases: :class:`magpie.api.schemas.InternalServerErrorResponseBodySchema`

   .. attribute:: user_name
      

      

   .. attribute:: provider_name
      

      


.. py:class:: Signin_POST_Internal_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Unknown login error.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Signin_POST_External_InternalServerErrorResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Error occurred while signing in with external provider.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Version_GET_ResponseBodySchema

   Bases: :class:`magpie.api.schemas.BaseResponseBodySchema`

   .. attribute:: version
      

      

   .. attribute:: db_version
      

      


.. py:class:: Version_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get version successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: Homepage_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      :annotation: = Get homepage successful.

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. py:class:: SwaggerAPI_GET_OkResponseSchema

   Bases: :class:`magpie.definitions.cornice_definitions.colander.MappingSchema`

   .. attribute:: description
      

      

   .. attribute:: header
      

      

   .. attribute:: body
      

      


.. data:: Resource_GET_responses
   

   

.. data:: Resource_PUT_responses
   

   

.. data:: Resources_GET_responses
   

   

.. data:: Resources_POST_responses
   

   

.. data:: Resources_DELETE_responses
   

   

.. data:: ResourcePermissions_GET_responses
   

   

.. data:: ServiceTypes_GET_responses
   

   

.. data:: ServiceType_GET_responses
   

   

.. data:: Services_GET_responses
   

   

.. data:: Services_POST_responses
   

   

.. data:: Service_GET_responses
   

   

.. data:: Service_PUT_responses
   

   

.. data:: Service_DELETE_responses
   

   

.. data:: ServicePermissions_GET_responses
   

   

.. data:: ServiceResources_GET_responses
   

   

.. data:: ServiceResources_POST_responses
   

   

.. data:: ServiceTypeResources_GET_responses
   

   

.. data:: ServiceTypeResourceTypes_GET_responses
   

   

.. data:: ServiceResource_DELETE_responses
   

   

.. data:: Users_GET_responses
   

   

.. data:: Users_POST_responses
   

   

.. data:: User_GET_responses
   

   

.. data:: User_PUT_responses
   

   

.. data:: User_DELETE_responses
   

   

.. data:: UserResources_GET_responses
   

   

.. data:: UserGroups_GET_responses
   

   

.. data:: UserGroups_POST_responses
   

   

.. data:: UserGroup_DELETE_responses
   

   

.. data:: UserResourcePermissions_GET_responses
   

   

.. data:: UserResourcePermissions_POST_responses
   

   

.. data:: UserResourcePermission_DELETE_responses
   

   

.. data:: UserServices_GET_responses
   

   

.. data:: UserServicePermissions_GET_responses
   

   

.. data:: UserServiceResources_GET_responses
   

   

.. data:: UserServicePermissions_POST_responses
   

   

.. data:: UserServicePermission_DELETE_responses
   

   

.. data:: LoggedUser_GET_responses
   

   

.. data:: LoggedUser_PUT_responses
   

   

.. data:: LoggedUser_DELETE_responses
   

   

.. data:: LoggedUserResources_GET_responses
   

   

.. data:: LoggedUserGroups_GET_responses
   

   

.. data:: LoggedUserGroups_POST_responses
   

   

.. data:: LoggedUserGroup_DELETE_responses
   

   

.. data:: LoggedUserResourcePermissions_GET_responses
   

   

.. data:: LoggedUserResourcePermissions_POST_responses
   

   

.. data:: LoggedUserResourcePermission_DELETE_responses
   

   

.. data:: LoggedUserServices_GET_responses
   

   

.. data:: LoggedUserServicePermissions_GET_responses
   

   

.. data:: LoggedUserServiceResources_GET_responses
   

   

.. data:: LoggedUserServicePermissions_POST_responses
   

   

.. data:: LoggedUserServicePermission_DELETE_responses
   

   

.. data:: Groups_GET_responses
   

   

.. data:: Groups_POST_responses
   

   

.. data:: Group_GET_responses
   

   

.. data:: Group_PUT_responses
   

   

.. data:: Group_DELETE_responses
   

   

.. data:: GroupUsers_GET_responses
   

   

.. data:: GroupServices_GET_responses
   

   

.. data:: GroupServicePermissions_GET_responses
   

   

.. data:: GroupServiceResources_GET_responses
   

   

.. data:: GroupResourcePermissions_POST_responses
   

   

.. data:: GroupServicePermissions_POST_responses
   

   

.. data:: GroupServicePermission_DELETE_responses
   

   

.. data:: GroupResources_GET_responses
   

   

.. data:: GroupResourcePermissions_GET_responses
   

   

.. data:: GroupResourcePermission_DELETE_responses
   

   

.. data:: Providers_GET_responses
   

   

.. data:: ProviderSignin_GET_responses
   

   

.. data:: Signin_POST_responses
   

   

.. data:: Signout_GET_responses
   

   

.. data:: Session_GET_responses
   

   

.. data:: Version_GET_responses
   

   

.. data:: Homepage_GET_responses
   

   

.. data:: SwaggerAPI_GET_responses
   

   

.. function:: api_schema(request)
   Return JSON Swagger specifications of Magpie REST API.


