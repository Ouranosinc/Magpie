:mod:`magpie.api.requests`
==========================

.. py:module:: magpie.api.requests


Module Contents
---------------

.. function:: get_request_method_content(request)

.. function:: get_multiformat_any(request, key, default=None) -> Any
   Obtains the ``key`` element from the request body using found `Content-Type` header.


.. function:: get_multiformat_post(request, key, default=None)

.. function:: get_multiformat_put(request, key, default=None)

.. function:: get_multiformat_delete(request, key, default=None)

.. function:: get_permission_multiformat_post_checked(request, service_or_resource, permission_name_key='permission_name') -> Permission
   Retrieves the permission from the body and validates that it is allowed for the specified `service` or `resource`.


.. function:: get_value_multiformat_post_checked(request, key, default=None)

.. function:: get_user(request, user_name_or_token=None) -> models.User

.. function:: get_user_matchdict_checked_or_logged(request, user_name_key='user_name')

.. function:: get_user_matchdict_checked(request, user_name_key='user_name')

.. function:: get_group_matchdict_checked(request, group_name_key='group_name')

.. function:: get_resource_matchdict_checked(request, resource_name_key='resource_id') -> models.Resource

.. function:: get_service_matchdict_checked(request, service_name_key='service_name')

.. function:: get_permission_matchdict_checked(request, service_or_resource, permission_name_key='permission_name') -> Permission
   Obtains the `permission` specified in the ``request`` path and validates that it is allowed for the specified
   ``service_or_resource`` which can be a `service` or a children `resource`.

   Allowed permissions correspond to the direct `service` permissions or restrained permissions of the `resource`
   under its root `service`.

   :returns: found permission name if valid for the service/resource


.. function:: get_value_matchdict_checked(request, key)

.. function:: get_query_param(request, case_insensitive_key, default=None) -> Any
   Retrieves a query string value by name (case insensitive), or returns the default if not present.


