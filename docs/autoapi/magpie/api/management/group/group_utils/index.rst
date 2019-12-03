:mod:`magpie.api.management.group.group_utils`
==============================================

.. py:module:: magpie.api.management.group.group_utils


Module Contents
---------------

.. function:: get_all_group_names(db_session) -> List[Str]
   Get all existing group names from the database.


.. function:: get_group_resources(group, db_session) -> JSON
   Get formatted JSON body describing all service resources the ``group`` as permissions on.


.. function:: create_group(group_name, db_session) -> HTTPException
   Creates a group if it is permitted and not conflicting.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


.. function:: create_group_resource_permission_response(group, resource, permission, db_session) -> HTTPException
   Creates a permission on a group/resource combination if it is permitted and not conflicting.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


.. function:: get_group_resources_permissions_dict(group, db_session, resource_ids=None, resource_types=None) -> JSON
   Get a dictionary of resources and corresponding permissions that a group has on the resources.

   Filter search by ``resource_ids`` and/or ``resource_types`` if specified.


.. function:: get_group_resource_permissions_response(group, resource, db_session) -> HTTPException
   Get validated response with group resource permissions as content.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


.. function:: delete_group_resource_permission_response(group, resource, permission, db_session) -> HTTPException
   Get validated response on deleted group resource permission.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


.. function:: get_group_services(resources_permissions_dict, db_session) -> JSON
   Nest and regroup the resource permissions under corresponding root service types.


.. function:: get_group_services_response(group, db_session) -> HTTPException
   Get validated response of services the group has permissions on.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


.. function:: get_group_service_permissions(group, service, db_session) -> List[Permission]
   Get all permissions the group has on a specific service.


.. function:: get_group_service_permissions_response(group, service, db_session) -> HTTPException
   Get validated response of found group service permissions.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


.. function:: get_group_service_resources_permissions_dict(group, service, db_session) -> JSON
   Get all permissions the group has on a specific service's children resources.


.. function:: get_group_service_resources_response(group, service, db_session) -> HTTPException
   Get validated response of all found service resources which the group has permissions on.

   :returns: valid HTTP response on successful operations.
   :raises HTTPException: error HTTP response of corresponding situation.


