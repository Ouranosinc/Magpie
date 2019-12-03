:mod:`magpie.ui.utils`
======================

.. py:module:: magpie.ui.utils


Module Contents
---------------

.. function:: check_response(response)

.. function:: request_api(request, path, method='GET', data=None, headers=None, cookies=None) -> Response
   Use a pyramid sub-request to request Magpie API routes via the UI. This avoids max retries and closed connections
   when using 1 worker (eg: during tests).

   Some information is retrieved from ``request`` to pass down to the sub-request (eg: cookies).
   If they are passed as argument, corresponding values will override the ones found in ``request``.

   All sub-requests to the API are assumed to be of ``magpie.common.CONTENT_TYPE_JSON`` unless explicitly overridden
   with ``headers``.


.. function:: error_badrequest(func)
   Decorator that encapsulates the operation in a try/except block, and returns HTTP Bad Request on exception.


