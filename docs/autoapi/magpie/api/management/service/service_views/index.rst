:mod:`magpie.api.management.service.service_views`
==================================================

.. py:module:: magpie.api.management.service.service_views


Module Contents
---------------

.. function:: get_service_types_view(request)
   List all available service types.


.. function:: get_services_by_type_view(request)
   List all registered services from a specific type.


.. function:: get_services_view(request)
   List all registered services.


.. function:: get_services_runner(request)

.. function:: register_service_view(request)
   Registers a new service.


.. function:: update_service_view(request)
   Update a service information.


.. function:: get_service_view(request)
   Get a service information.


.. function:: unregister_service_view(request)
   Unregister a service.


.. function:: get_service_permissions_view(request)
   List all applicable permissions for a service.


.. function:: delete_service_resource_view(request)
   Unregister a resource.


.. function:: get_service_resources_view(request)
   List all resources registered under a service.


.. function:: create_service_direct_resource_view(request)
   Register a new resource directly under a service.


.. function:: get_service_type_resources_view(request)
   List details of resource types supported under a specific service type.


.. function:: get_service_type_resource_types_view(request)
   List all resource types supported under a specific service type.


