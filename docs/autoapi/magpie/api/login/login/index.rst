:mod:`magpie.api.login.login`
=============================

.. py:module:: magpie.api.login.login


Module Contents
---------------

.. data:: LOGGER
   

   

.. data:: MAGPIE_DEFAULT_PROVIDER
   

   

.. data:: MAGPIE_INTERNAL_PROVIDERS
   

   

.. data:: MAGPIE_EXTERNAL_PROVIDERS
   

   

.. data:: MAGPIE_PROVIDER_KEYS
   

   

.. function:: process_sign_in_external(request, username, provider)

.. function:: verify_provider(provider_name)

.. function:: sign_in(request)
   Signs in a user session.


.. function:: login_success_ziggurat(request)

.. function:: login_failure(request, reason=None)

.. function:: new_user_external(external_user_name, external_id, email, provider_name, db_session)
   Create new user with an External Identity.


.. function:: login_success_external(request, external_user_name, external_id, email, provider_name)

.. function:: authomatic_login(request)
   Signs in a user session using an external provider.


.. function:: sign_out(request)
   Signs out the current user session.


.. function:: get_session(request)
   Get information about current session.


.. function:: get_providers(request)
   Get list of login providers.


