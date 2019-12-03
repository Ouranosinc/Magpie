:mod:`magpie.owsrequest`
========================

.. py:module:: magpie.owsrequest

.. autoapi-nested-parse::

   The OWSRequest is based on pywps code:

   * https://github.com/geopython/pywps/tree/pywps-3.2/pywps/Parser
   * https://github.com/geopython/pywps/blob/master/pywps/app/WPSRequest.py



Module Contents
---------------

.. data:: LOGGER
   

   

.. function:: ows_parser_factory(request) -> OWSParser
   Retrieve the appropriate ``OWSParser`` parser using the ``Content-Type`` header.

   If the ``Content-Type`` header is missing or 'text/plain', and the request has a body,
   try to parse the body as JSON and set the content-type to 'application/json'.

   'application/x-www-form-urlencoded' ``Content-Type`` header is also handled correctly.

   Otherwise, use the GET/POST WPS parsers.


.. py:class:: OWSParser(request)

   Bases: :class:`object`

   
   .. method:: parse(self, param_list)



   
   .. method:: _get_param_value(self, param)




.. py:class:: WPSGet(request)

   Bases: :class:`magpie.owsrequest.OWSParser`

   Basically a case-insensitive query string parser

   
   .. method:: _request_params(self)



   
   .. method:: _get_param_value(self, param)




.. function:: lxml_strip_ns(tree)

.. py:class:: WPSPost(request)

   Bases: :class:`magpie.owsrequest.OWSParser`

   
   .. method:: _get_param_value(self, param)




.. py:class:: MultiFormatParser

   Bases: :class:`magpie.owsrequest.OWSParser`

   
   .. method:: _get_param_value(self, param)




