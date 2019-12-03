:mod:`magpie.ui.management.views`
=================================

.. py:module:: magpie.ui.management.views


Module Contents
---------------

.. data:: LOGGER
   

   

.. py:class:: ManagementViews(request)

   Bases: :class:`object`

   
   .. method:: get_all_groups(self, first_default_group=None)



   
   .. method:: get_group_users(self, group_name)



   
   .. method:: get_user_groups(self, user_name)



   
   .. method:: get_user_names(self)



   
   .. method:: get_user_emails(self)



   
   .. method:: get_resource_types(self)

      :return: dictionary of all resources as {id: 'resource_type'}
      :rtype: dict



   
   .. method:: get_services(self, cur_svc_type)



   
   .. method:: get_service_data(self, service_name)



   
   .. method:: get_service_types(self)



   
   .. method:: update_service_name(self, old_service_name, new_service_name, service_push)



   
   .. method:: update_service_url(self, service_name, new_service_url, service_push)



   
   .. method:: goto_service(self, resource_id)



   
   .. staticmethod:: flatten_tree_resource(resource_node, resource_dict)

      :param resource_node: any-level dictionary composing the resources tree
      :param resource_dict: reference of flattened dictionary across levels
      :return: flattened dictionary `resource_dict` of all {id: 'resource_type'}
      :rtype: dict



   
   .. method:: view_users(self)



   
   .. method:: add_user(self)



   
   .. method:: edit_user(self)



   
   .. method:: view_groups(self)



   
   .. method:: add_group(self)



   
   .. method:: resource_tree_parser(self, raw_resources_tree, permission)



   
   .. method:: perm_tree_parser(self, raw_perm_tree)



   
   .. staticmethod:: default_get(dictionary, key, default)



   
   .. method:: edit_group_users(self, group_name)



   
   .. method:: edit_user_or_group_resource_permissions(self, user_or_group_name, resource_id, is_user=False)



   
   .. method:: get_user_or_group_resources_permissions_dict(self, user_or_group_name, services, service_type, is_user=False, is_inherit_groups_permissions=False)



   
   .. method:: update_user_or_group_resources_permissions_dict(self, res_perms, res_id, removed_perms, new_perms)



   
   .. method:: edit_group(self)



   
   .. staticmethod:: make_sync_error_message(service_names)



   
   .. method:: get_remote_resources_info(self, res_perms, services, session)



   
   .. staticmethod:: merge_remote_resources(res_perms, services, session)



   
   .. staticmethod:: get_last_sync_datetimes(service_ids, session)



   
   .. method:: delete_resource(self, res_id)



   
   .. method:: get_ids_to_clean(self, resources)



   
   .. method:: add_remote_resource(self, service_type, services_names, user_or_group, remote_id, is_user=False)



   
   .. method:: get_service_resources(self, service_name)



   
   .. method:: view_services(self)



   
   .. method:: add_service(self)



   
   .. method:: edit_service(self)



   
   .. method:: add_resource(self)




