:mod:`magpie.adapter.magpieowssecurity`
=======================================

.. py:module:: magpie.adapter.magpieowssecurity


Module Contents
---------------

.. data:: LOGGER
   

   

.. py:class:: MagpieOWSSecurity(request)

   Bases: :class:`magpie.definitions.twitcher_definitions.OWSSecurityInterface`

   
   .. method:: check_request(self, request)



   
   .. method:: update_request_cookies(self, request)

      Ensure login of the user and update the request cookies if Twitcher is in a special configuration.

      Only update if `MAGPIE_COOKIE_NAME` is missing and is retrievable from `access_token` in `Authorization` header.
      Counter-validate the login procedure by calling Magpie's `/session` which should indicated a logged user.




