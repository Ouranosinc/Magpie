:mod:`magpie.api.management.resource.resource_formats`
======================================================

.. py:module:: magpie.api.management.resource.resource_formats


Module Contents
---------------

.. function:: format_resource(resource, permissions=None, basic_info=False)
   Formats the ``resource`` information into JSON.


.. function:: format_resource_tree(children, db_session, resources_perms_dict=None, internal_svc_res_perm_dict=None)
   Generates the formatted service/resource tree with all its children resources by calling :function:`format_resource`
   recursively.

   Filters resource permissions with ``resources_perms_dict`` if provided.

   :param children: service or resource for which to generate the formatted resource tree
   :param db_session: connection to db
   :param resources_perms_dict: any pre-established user- or group-specific permissions. Only those are shown if given.
   :param internal_svc_res_perm_dict: *for this function's use only*,
       avoid re-fetch of already obtained permissions for corresponding resources
   :return: formatted resource tree


.. function:: get_resource_children(resource, db_session)

.. function:: format_resource_with_children(resource, db_session)

