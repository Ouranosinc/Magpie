:mod:`magpie.api.management.user.user_utils`
============================================

.. py:module:: magpie.api.management.user.user_utils


Module Contents
---------------

.. function:: create_user(user_name, password, email, group_name, db_session) -> HTTPException
   Creates a user if it is permitted and not conflicting. Password must be set to `None` if using external identity.

   Created user will be part of group matching ``group_name`` (can be ``MAGPIE_ANONYMOUS_GROUP`` for minimal access).
   Furthermore, the user will also *always* be associated with ``MAGPIE_ANONYMOUS_GROUP`` (if not already explicitly
   requested with ``group_name``) to allow access to resources with public permission. The ``group_name`` **must**
   be an existing group.

   :returns: valid HTTP response on successful operation.


.. function:: create_user_resource_permission_response(user, resource, permission, db_session) -> HTTPException
   Creates a permission on a user/resource combination if it is permitted and not conflicting.

   :returns: valid HTTP response on successful operation.


.. function:: delete_user_resource_permission_response(user, resource, permission, db_session) -> HTTPException
   Get validated response on deleted user resource permission.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


.. function:: get_resource_root_service(resource, request) -> ServiceInterface
   Retrieves the service class corresponding to the specified resource's root service-resource.


.. function:: filter_user_permission(resource_permission_list, user) -> Iterable[ResourcePermissionType]
   Retrieves only direct user permissions on resources amongst a list of user/group resource/service permissions.


.. function:: get_user_resource_permissions_response(user, resource, request, inherit_groups_permissions=True, effective_permissions=False) -> HTTPException
   Retrieves user resource permissions with or without inherited group permissions. Alternatively retrieves the
   effective user resource permissions, where group permissions are implied as `True`.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


.. function:: get_user_services(user, request, cascade_resources=False, inherit_groups_permissions=False, format_as_list=False) -> UserServicesType
   Returns services by type with corresponding services by name containing sub-dict information.

   :param user: user for which to find services
   :param request: request with database session connection
   :param cascade_resources:
       If `False`, return only services with *Direct* user permissions on their corresponding service-resource.
       Otherwise, return every service that has at least one sub-resource with user permissions.
   :param inherit_groups_permissions:
       If `False`, return only user-specific service/sub-resources permissions.
       Otherwise, resolve inherited permissions using all groups the user is member of.
   :param format_as_list:
       returns as list of service dict information (not grouped by type and by name)
   :return: only services which the user as *Direct* or *Inherited* permissions, according to `inherit_from_resources`
   :rtype:
       dict of services by type with corresponding services by name containing sub-dict information,
       unless `format_as_list` is `True`


.. function:: get_user_service_permissions(user, service, request, inherit_groups_permissions=True) -> List[Permission]

.. function:: get_user_resources_permissions_dict(user, request, resource_types=None, resource_ids=None, inherit_groups_permissions=True) -> Dict[Str, Any]
   Creates a dictionary of resources by id with corresponding permissions of the user.

   :param user: user for which to find services
   :param request: request with database session connection
   :param resource_types: filter the search query with specified resource types
   :param resource_ids: filter the search query with specified resource ids
   :param inherit_groups_permissions:
       If `False`, return only user-specific resource permissions.
       Otherwise, resolve inherited permissions using all groups the user is member of.
   :return: only services which the user as *Direct* or *Inherited* permissions, according to `inherit_from_resources`


.. function:: get_user_service_resources_permissions_dict(user, service, request, inherit_groups_permissions=True) -> Dict[Str, Any]

.. function:: check_user_info(user_name, email, password, group_name) -> None

.. function:: get_user_groups_checked(request, user) -> List[Str]

