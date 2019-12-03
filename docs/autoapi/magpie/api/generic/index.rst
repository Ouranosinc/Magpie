:mod:`magpie.api.generic`
=========================

.. py:module:: magpie.api.generic


Module Contents
---------------

.. data:: LOGGER
   

   

.. function:: internal_server_error(request) -> HTTPException
   Overrides default HTTP.


.. function:: not_found_or_method_not_allowed(request) -> HTTPException
   Overrides the default ``HTTPNotFound`` [404] by appropriate ``HTTPMethodNotAllowed`` [405] when applicable.

   Not found response can correspond to underlying process operation not finding a required item, or a completely
   unknown route (path did not match any existing API definition).
   Method not allowed is more specific to the case where the path matches an existing API route, but the specific
   request method (GET, POST, etc.) is not allowed on this path.

   Without this fix, both situations return [404] regardless.


.. function:: unauthorized_or_forbidden(request) -> HTTPException
   Overrides the default ``HTTPForbidden`` [403] by appropriate ``HTTPUnauthorized`` [401] when applicable.

   Unauthorized response is for restricted user access according to credentials and/or authorization headers.
   Forbidden response is for operation refused by the underlying process operations.

   Without this fix, both situations return [403] regardless.

   .. seealso::
       http://www.restapitutorial.com/httpstatuscodes.html


.. function:: validate_accept_header_tween(handler, registry)
   Tween that validates that the specified request ``Accept`` header (if any), is a supported one by the application.

   :raises HTTPNotAcceptable: if `Accept` header was specified and is not supported.


.. function:: get_request_info(request, default_message='undefined', exception_details=False) -> JSON
   Obtains additional content details about the ``request`` according to available information.


