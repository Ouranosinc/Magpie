:mod:`magpie.adapter`
=====================

.. py:module:: magpie.adapter


Submodules
----------
.. toctree::
   :titlesonly:
   :maxdepth: 1

   magpieowssecurity/index.rst
   magpieservice/index.rst


Package Contents
----------------

.. data:: SigninAPI
   

   

.. function:: valid_http(httpSuccess=HTTPOk, httpKWArgs=None, detail='', content=None, contentType=CONTENT_TYPE_JSON) -> HTTPException
   Returns successful HTTP with standardized information formatted with content type. (see :function:`raise_http` for
   HTTP error calls)

   :param httpSuccess: any derived class from base `HTTPSuccessful` (default: `HTTPOk`)
   :param httpKWArgs: additional keyword arguments to pass to `httpSuccess` when called
   :param detail: additional message information (default: empty)
   :param content: json formatted content to include
   :param contentType: format in which to return the exception (one of `magpie.common.SUPPORTED_CONTENT_TYPES`)
   :return `HTTPSuccessful`: formatted successful with additional details and HTTP code


.. function:: raise_http(httpError=HTTPInternalServerError, httpKWArgs=None, detail='', content=None, contentType=CONTENT_TYPE_JSON, nothrow=False) -> Optional[HTTPException]
   Raises error HTTP with standardized information formatted with content type.

   The content contains the corresponding http error code, the provided message as detail and
   optional specified additional json content (kwarg dict).

   .. seealso::
       :func:`valid_http` for HTTP successful calls

   :param httpError: any derived class from base `HTTPError` (default: `HTTPInternalServerError`)
   :param httpKWArgs: additional keyword arguments to pass to `httpError` if called in case of HTTP exception
   :param detail: additional message information (default: empty)
   :param content: json formatted content to include
   :param contentType: format in which to return the exception (one of `magpie.common.SUPPORTED_CONTENT_TYPES`)
   :param nothrow: returns the error response instead of raising it automatically, but still handles execution errors
   :raises HTTPError: formatted raised exception with additional details and HTTP code
   :returns: HTTPError formatted exception with additional details and HTTP code only if `nothrow` is `True`


.. py:class:: MagpieOWSSecurity(request)

   Bases: :class:`magpie.definitions.twitcher_definitions.OWSSecurityInterface`

   
   .. method:: check_request(self, request)



   
   .. method:: update_request_cookies(self, request)

      Ensure login of the user and update the request cookies if Twitcher is in a special configuration.

      Only update if `MAGPIE_COOKIE_NAME` is missing and is retrievable from `access_token` in `Authorization` header.
      Counter-validate the login procedure by calling Magpie's `/session` which should indicated a logged user.




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




.. function:: get_auth_config(container)

.. function:: get_session_factory(engine)

.. function:: get_tm_session(session_factory, transaction_manager)
   Get a ``sqlalchemy.orm.Session`` instance backed by a transaction.

   This function will hook the session to the transaction manager which
   will take care of committing any changes.

   - When using pyramid_tm it will automatically be committed or aborted
     depending on whether an exception is raised.

   - When using scripts you should wrap the session in a manager yourself.
     For example::

         import transaction

         engine = get_engine(settings)
         session_factory = get_session_factory(engine)
         with transaction.manager:
             db_session = get_tm_session(session_factory, transaction.manager)


.. function:: get_engine(container=None, prefix='sqlalchemy.', **kwargs) -> Engine

.. function:: get_logger(name, level=None)
   Immediately sets the logger level to avoid duplicate log outputs from the `root logger` and `this logger` when
   `level` is `NOTSET`.


.. function:: get_settings(container) -> SettingsType

.. function:: get_magpie_url(container=None) -> Str

.. data:: CONTENT_TYPE_JSON
   :annotation: = application/json

   

.. data:: LOGGER
   

   

.. function:: debug_cookie_identify(request)
   Logs debug information about request cookie.

   .. WARNING::

       This function is intended for debugging purposes only. It reveals sensible configuration information.

   Re-implements basic functionality of :func:`pyramid.AuthTktAuthenticationPolicy.cookie.identify` called via
   :func:`request.unauthenticated_userid` within :func:`get_user` to provide additional logging.

   .. seealso::
       - :class:`pyramid.authentication.AuthTktCookieHelper`
       - :class:`pyramid.authentication.AuthTktAuthenticationPolicy`


.. function:: get_user(request)

.. function:: verify_user(request)

.. py:class:: _Singleton

   Bases: :class:`type`

   A metaclass that creates a Singleton base class when called.

   .. attribute:: _instances
      

      

   
   .. method:: __call__(cls, *args, **kwargs)




.. py:class:: Singleton

   Bases: :class:`magpie.adapter._Singleton`


.. py:class:: MagpieAdapter(container)

   Bases: :class:`magpie.definitions.twitcher_definitions.AdapterInterface`, :class:`magpie.adapter.Singleton`

   
   .. method:: describe_adapter(self)



   
   .. method:: servicestore_factory(self, request, headers=None)



   
   .. method:: owssecurity_factory(self, request)



   
   .. method:: owsproxy_config(self, container)



   
   .. method:: configurator_factory(self, container)




