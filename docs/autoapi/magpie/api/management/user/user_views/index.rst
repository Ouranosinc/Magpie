:mod:`magpie.api.management.user.user_views`
============================================

.. py:module:: magpie.api.management.user.user_views


Module Contents
---------------

.. data:: LOGGER
   

   

.. function:: get_users_view(request)
   List all registered user names.


.. function:: create_user_view(request)
   Create a new user.


.. function:: update_user_view(request)
   Update user information by user name.


.. function:: get_user_view(request)
   Get user information by name.


.. function:: delete_user_view(request)
   Delete a user by name.


.. function:: get_user_groups_view(request)
   List all groups a user belongs to.


.. function:: assign_user_group_view(request)
   Assign a user to a group.


.. function:: delete_user_group_view(request)
   Remove a user from a group.


.. function:: get_user_resources_view(request)
   List all resources a user has permissions on.


.. function:: get_user_inherited_resources_view(request)
   [DEPRECATED: use '/users/{user_name}/resources?inherit=true']
   List all resources a user has permissions on with his inherited user and groups permissions.


.. function:: get_user_resource_permissions_view(request)
   List all permissions a user has on a specific resource.


.. function:: get_user_resource_inherit_groups_permissions_view(request)
   [DEPRECATED: use '/users/{user_name}/resources/{resource_id}/permissions?inherit=true']
   List all permissions a user has on a specific resource with his inherited user and groups permissions.


.. function:: create_user_resource_permission_view(request)
   Create a permission on specific resource for a user.


.. function:: delete_user_resource_permission_view(request)
   Delete a direct permission on a resource for a user (not including his groups permissions).


.. function:: get_user_services_view(request)
   List all services a user has permissions on.


.. function:: get_user_inherited_services_view(request)
   [DEPRECATED: use '/users/{user_name}/services?inherit=true']
   List all services a user has permissions on with his inherited user and groups permissions.


.. function:: get_user_service_inherited_permissions_view(request)
   [DEPRECATED: use '/users/{user_name}/services/{service_name}/permissions?inherit=true']
   List all permissions a user has on a service using all his inherited user and groups permissions.


.. function:: get_user_service_permissions_view(request)
   List all permissions a user has on a service.


.. function:: create_user_service_permission_view(request)
   Create a permission on a service for a user.


.. function:: delete_user_service_permission_view(request)
   Delete a direct permission on a service for a user (not including his groups permissions).


.. function:: get_user_service_resources_view(request)
   List all resources under a service a user has permission on.


.. function:: get_user_service_inherited_resources_view(request)
   [DEPRECATED: use '/users/{user_name}/services/{service_name}/resources?inherit=true']
   List all resources under a service a user has permission on using all his inherited user and groups permissions.


