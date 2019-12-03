:mod:`magpie.api.management.service.service_formats`
====================================================

.. py:module:: magpie.api.management.service.service_formats


Module Contents
---------------

.. function:: format_service(service, permissions=None, show_private_url=False, show_resources_allowed=False) -> JSON
   Formats the ``service`` information into JSON.

   Note:
       Automatically finds ``permissions`` of the service if not specified.
       To preserve `empty` permissions such as during listing of `user`/`group` resource permissions,
       an empty ``list`` should be specified.


.. function:: format_service_resources(service, db_session, service_perms=None, resources_perms_dict=None, show_all_children=False, show_private_url=True) -> JSON
   Formats the service and its resource tree as a JSON body.

   :param service: service for which to display details with sub-resources
   :param db_session: database session
   :param service_perms: permissions to display instead of specific ``service``-type ones
   :param resources_perms_dict: permission(s) of resource(s) id(s) to *preserve* if ``resources_perms_dict = False``
   :param show_all_children: display all children resources recursively, or only ones matching ``resources_perms_dict``
   :param show_private_url: displays the
   :return: JSON body representation of the service resource tree


.. function:: format_service_resource_type(resource_class, service_class) -> JSON

