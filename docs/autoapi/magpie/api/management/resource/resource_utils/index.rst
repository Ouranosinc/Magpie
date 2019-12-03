:mod:`magpie.api.management.resource.resource_utils`
====================================================

.. py:module:: magpie.api.management.resource.resource_utils


Module Contents
---------------

.. function:: check_valid_service_or_resource_permission(permission_name, service_or_resource, db_session) -> Optional[Permission]
   Checks if a permission is valid to be applied to a specific `service` or a `resource` under a root service.

   :param permission_name: permission name to be validated
   :param service_or_resource: resource item corresponding to either a Service or a Resource
   :param db_session: db connection
   :return: valid Permission if allowed by the service/resource


.. function:: check_valid_service_resource(parent_resource, resource_type, db_session)
   Checks if a new Resource can be contained under a parent Resource given the requested type and the corresponding
   Service under which the parent Resource is already assigned.

   :param parent_resource: Resource under which the new resource of `resource_type` must be placed
   :param resource_type: desired resource type
   :param db_session:
   :return: root Service if all checks were successful


.. function:: crop_tree_with_permission(children, resource_id_list)

.. function:: get_resource_path(resource_id, db_session)

.. function:: get_service_or_resource_types(service_or_resource) -> Tuple[Type[ServiceInterface], Str]
   Obtain the `service` or `resource` class and a corresponding ``"service"`` or ``"resource"`` type identifier.


.. function:: get_resource_permissions(resource, db_session) -> List[Permission]

.. function:: get_resource_root_service(resource, db_session) -> Optional[models.Resource]
   Recursively rewinds back through the top of the resource tree up to the top-level service-resource.

   :param resource: initial resource where to start searching upwards the tree
   :param db_session:
   :return: resource-tree root service as a resource object


.. function:: create_resource(resource_name, resource_display_name, resource_type, parent_id, db_session) -> HTTPException

.. function:: delete_resource(request)

