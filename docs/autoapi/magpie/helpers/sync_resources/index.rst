:mod:`magpie.helpers.sync_resources`
====================================

.. py:module:: magpie.helpers.sync_resources

.. autoapi-nested-parse::

   Synchronize local and remote resources.

   To implement a new service, see the _SyncServiceInterface class.



Module Contents
---------------

.. data:: LOGGER
   

   

.. data:: CRON_SERVICE
   :annotation: = False

   

.. data:: OUT_OF_SYNC
   

   

.. function:: merge_local_and_remote_resources(resources_local, service_sync_type, service_id, session)
   Main function to sync resources with remote server.


.. function:: _merge_resources(resources_local, resources_remote, max_depth=None)
   Merge resources_local and resources_remote, adding the following keys to the output:

       - remote_id: id of the RemoteResource
       - matches_remote: True or False depending if the resource is present on the remote server

   :returns: dictionary of the form validated by `magpie.helpers.sync_services.is_valid_resource_schema`.


.. function:: _sort_resources(resources)
   Sorts a resource dictionary of the type validated by 'sync_services.is_valid_resource_schema' by using an
   OrderedDict.

   :return: None


.. function:: _ensure_sync_info_exists(service_resource_id, session)
   Make sure the RemoteResourcesSyncInfo entry exists in the database.

   :param service_resource_id:
   :param session:


.. function:: _get_remote_resources(service)
   Request remote resources, depending on service type.

   :param service: (models.Service)
   :return:


.. function:: _delete_records(service_id, session)
   Delete all RemoteResource based on a Service.resource_id.

   :param service_id:
   :param session:


.. function:: _create_main_resource(service_id, session)
   Creates a main resource for a service, whether one currently exists or not.

   Each RemoteResourcesSyncInfo has a main RemoteResource of the same name as the service.
   This is similar to the Service and Resource relationship.

   :param service_id:
   :param session:


.. function:: _update_db(remote_resources, service_id, session)
   Writes remote resources to database.

   :param remote_resources:
   :param service_id:
   :param session:


.. function:: _get_resource_children(resource, db_session)
   Mostly copied from ziggurat_foundations to use RemoteResource instead of Resource.

   :param resource:
   :param db_session:
   :return:


.. function:: _format_resource_tree(children)

.. function:: _query_remote_resources_in_database(service_id, session)
   Reads remote resources from the RemoteResources table. No external request is made.

   :return: a dictionary of the form defined in 'sync_services.is_valid_resource_schema'


.. function:: get_last_sync(service_id, session) -> Optional[datetime.datetime]

.. function:: fetch_all_services_by_type(service_type, session)
   Get remote resources for all services of a certain type.

   :param service_type:
   :param session:


.. function:: fetch_single_service(service, session)
   Get remote resources for a single service.

   :param service: (models.Service) or service_id
   :param session:


.. function:: fetch()
   Main function to get all remote resources for each service and write to database.


.. function:: setup_cron_logger()

.. function:: main()
   Main entry point for cron service.


