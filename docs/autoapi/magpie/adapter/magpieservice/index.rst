:mod:`magpie.adapter.magpieservice`
===================================

.. py:module:: magpie.adapter.magpieservice

.. autoapi-nested-parse::

   Store adapters to read data from magpie.



Module Contents
---------------

.. data:: LOGGER
   

   

.. py:class:: MagpieServiceStore(request)

   Bases: :class:`magpie.definitions.twitcher_definitions.ServiceStoreInterface`

   Registry for OWS services.

   Uses magpie to fetch service url and attributes.

   
   .. method:: save_service(self, service, overwrite=True, request=None)

      Magpie store is read-only, use magpie api to add services.



   
   .. method:: delete_service(self, name, request=None)

      Magpie store is read-only, use magpie api to delete services.



   
   .. method:: list_services(self, request=None)

      Lists all services registered in magpie.



   
   .. method:: fetch_by_name(self, name, visibility=None, request=None)

      Gets service for given ``name`` from magpie.



   
   .. method:: fetch_by_url(self, url, request=None)

      Gets service for given ``url`` from mongodb storage.



   
   .. method:: clear_services(self, request=None)

      Magpie store is read-only, use magpie api to delete services.




