:mod:`magpie.api.management.service.service_utils`
==================================================

.. py:module:: magpie.api.management.service.service_utils


Module Contents
---------------

.. data:: LOGGER
   

   

.. function:: create_service(service_name, service_type, service_url, service_push, db_session) -> HTTPException
   Generates an instance to register a new service.


.. function:: get_services_by_type(service_type, db_session)

.. function:: add_service_getcapabilities_perms(service, db_session, group_name=None)

