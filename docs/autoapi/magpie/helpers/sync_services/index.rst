:mod:`magpie.helpers.sync_services`
===================================

.. py:module:: magpie.helpers.sync_services


Module Contents
---------------

.. function:: is_valid_resource_schema(resources) -> bool
   Returns ``True`` if the structure of the input dictionary is a tree of the form::

   {
       "resource_name_1": {
           "children": {
               "resource_name_3": {"children": {}},
               "resource_name_4": {"children": {}}
           }
       }
       "resource_name_2": {"children": {}}
   }


.. py:class:: SyncServiceInterface(service_name, url)

   Bases: :class:`six.with_metaclass()`

   .. attribute:: sync_type
      :annotation: :Str

      

   .. attribute:: max_depth
      

      The max depth at which remote resources are fetched.


   
   .. method:: get_resources(self)

      This is the function actually fetching the data from the remote service. Implement this for every specific
      service.

      :return: The returned dictionary must be validated by 'is_valid_resource_schema'




.. py:class:: SyncServiceGeoserver

   Bases: :class:`magpie.helpers.sync_services.SyncServiceInterface`

   .. attribute:: sync_type
      :annotation: = geoserver-api

      

   .. attribute:: max_depth
      

      

   
   .. method:: get_resources(self)




.. py:class:: SyncServiceProjectAPI

   Bases: :class:`magpie.helpers.sync_services.SyncServiceInterface`

   .. attribute:: sync_type
      :annotation: = project-api

      

   .. attribute:: max_depth
      

      

   
   .. method:: get_resources(self)




.. py:class:: SyncServiceThredds

   Bases: :class:`magpie.helpers.sync_services.SyncServiceInterface`

   .. attribute:: sync_type
      :annotation: = thredds

      

   .. attribute:: max_depth
      

      

   
   .. staticmethod:: _resource_id(resource)



   
   .. method:: get_resources(self)




.. py:class:: SyncServiceDefault

   Bases: :class:`magpie.helpers.sync_services.SyncServiceInterface`

   .. attribute:: max_depth
      

      

   
   .. method:: get_resources(self)




.. data:: SYNC_SERVICES_TYPES
   :annotation: :Dict[Str, Type[SyncServiceInterface]]

   

