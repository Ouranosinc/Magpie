:mod:`magpie.api.management.group.group_views`
==============================================

.. py:module:: magpie.api.management.group.group_views


Module Contents
---------------

.. function:: get_groups_view(request)
   Get list of group names.


.. function:: create_group_view(request)
   Create a group.


.. function:: get_group_view(request)
   Get group information.


.. function:: edit_group_view(request)
   Update a group by name.


.. function:: delete_group_view(request)
   Delete a group by name.


.. function:: get_group_users_view(request)
   List all user from a group.


.. function:: get_group_services_view(request)
   List all services a group has permission on.


.. function:: get_group_service_permissions_view(request)
   List all permissions a group has on a specific service.


.. function:: create_group_service_permission_view(request)
   Create a permission on a specific resource for a group.


.. function:: delete_group_service_permission_view(request)
   Delete a permission from a specific service for a group.


.. function:: get_group_resources_view(request)
   List all resources a group has permission on.


.. function:: get_group_resource_permissions_view(request)
   List all permissions a group has on a specific resource.


.. function:: create_group_resource_permission_view(request)
   Create a permission on a specific resource for a group.


.. function:: delete_group_resource_permission_view(request)
   Delete a permission from a specific resource for a group.


.. function:: get_group_service_resources_view(request)
   List all resources under a service a group has permission on.


