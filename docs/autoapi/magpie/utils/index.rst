:mod:`magpie.utils`
===================

.. py:module:: magpie.utils


Module Contents
---------------

.. data:: CONTENT_TYPE_ANY
   :annotation: = */*

   

.. data:: CONTENT_TYPE_JSON
   :annotation: = application/json

   

.. data:: CONTENT_TYPE_FORM
   :annotation: = application/x-www-form-urlencoded

   

.. data:: CONTENT_TYPE_HTML
   :annotation: = text/html

   

.. data:: CONTENT_TYPE_PLAIN
   :annotation: = text/plain

   

.. data:: SUPPORTED_CONTENT_TYPES
   

   

.. function:: get_logger(name, level=None)
   Immediately sets the logger level to avoid duplicate log outputs from the `root logger` and `this logger` when
   `level` is `NOTSET`.


.. data:: LOGGER
   

   

.. function:: print_log(msg, logger=None, level=logging.INFO) -> None

.. function:: raise_log(msg, exception=Exception, logger=None, level=logging.ERROR) -> None

.. function:: bool2str(value) -> Str

.. function:: islambda(func)

.. function:: isclass(obj)
   Evaluate an object for class type (ie: class definition, not an instance nor any other type).

   :param obj: object to evaluate for class type
   :return: (bool) indicating if `object` is a class


.. function:: make_dirs(path)

.. function:: get_settings_from_config_ini(config_ini_path, ini_main_section_name='app:magpie_app')

.. function:: get_json(response)
   Retrieves the 'JSON' body of a response using the property/callable according to the response's implementation.


.. function:: get_header(header_name, header_container, default=None, split=None) -> Optional[Str]
   Retrieves ``header_name`` by fuzzy match (independently of upper/lower-case and underscore/dash) from various
   framework implementations of ``Headers``.

   If ``split`` is specified, the matched ``header_name`` is first split with it and the first item is returned.
   This allows to parse complex headers (e.g.: ``text/plain; charset=UTF-8`` to ``text/plain`` with ``split=';'``).

   :param header_name: header to find.
   :param header_container: where to look for `header_name`.
   :param default: value to returned if `header_container` is invalid or `header_name` could not be found.
   :param split: character(s) to use to split the *found* `header_name`.


.. function:: convert_response(response) -> Response
   Converts a ``response`` implementation (e.g.: ``requests.Response``) to an equivalent ``pyramid.response.Response``
   version.


.. function:: get_admin_cookies(container, verify=True, raise_message=None) -> CookiesType

.. function:: get_settings(container) -> SettingsType

.. function:: patch_magpie_url(container) -> SettingsType
   Updates potentially missing configuration settings for normal application execution.


.. function:: get_magpie_url(container=None) -> Str

.. function:: get_phoenix_url(container=None) -> Str

.. function:: get_twitcher_protected_service_url(magpie_service_name, hostname=None)

.. function:: log_request_format(request) -> Str

.. function:: log_request(event)
   Subscriber event that logs basic details about the incoming requests.


.. function:: log_exception_tween(handler, registry)
   Tween factory that logs any exception before re-raising it.

   Application errors are marked as ``ERROR`` while non critical HTTP errors are marked as ``WARNING``.


.. py:class:: ExtendedEnumMeta

   Bases: :class:`enum.EnumMeta`

   
   .. method:: names(cls)

      Returns the member names assigned to corresponding enum elements.



   
   .. method:: values(cls)

      Returns the literal values assigned to corresponding enum elements.



   
   .. method:: get(cls, key_or_value, default=None)

      Finds an enum entry by defined name or its value.

      Returns the entry directly if it is already a valid enum.




.. function:: is_json_body(body)

