"""
The OWSRequest is based on pywps code:

* https://github.com/geopython/pywps/tree/pywps-3.2/pywps/Parser
* https://github.com/geopython/pywps/blob/master/pywps/app/WPSRequest.py
"""

import abc
from typing import TYPE_CHECKING

import lxml.etree  # nosec: B410 # module safe but bandit flags it : https://github.com/tiran/defusedxml/issues/38

from magpie.api.requests import get_multiformat_body
from magpie.utils import CONTENT_TYPE_FORM, CONTENT_TYPE_JSON, CONTENT_TYPE_PLAIN, get_header, get_logger, is_json_body

if TYPE_CHECKING:
    from pyramid.request import Request
LOGGER = get_logger(__name__)


def ows_parser_factory(request):
    # type: (Request) -> OWSParser
    """
    Retrieve the appropriate :class:`OWSParser` parser using the ``Content-Type`` header.

    If the ``Content-Type`` header is missing or ``text/plain``, and the request has a body,
    try to parse the body as JSON and set the content-type to ``application/json`` if successful.

    Handle XML-like ``Content-Type`` headers such as ``application/x-www-form-urlencoded`` whenever applicable.

    Otherwise, use the basic :class:`OWSGetParser` or :class:`OWSPostParser` according to the presence of a body.
    These provide minimal parsing to handle most typical `OGC Web Services` (:term:`OWS`) request parameters.
    """
    content_type = get_header("Content-Type", request.headers, default=None, split=";,")

    if content_type is None or content_type == CONTENT_TYPE_PLAIN:
        if is_json_body(request.body):
            # default to json when can be parsed as json
            request.headers["Content-Type"] = request.content_type = content_type = CONTENT_TYPE_JSON

    if content_type in (CONTENT_TYPE_JSON, CONTENT_TYPE_FORM):
        return MultiFormatParser(request)

    if request.body:
        return OWSPostParser(request)

    return OWSGetParser(request)


class OWSParser(object):

    def __init__(self, request):
        self.request = request
        self.params = {}

    def parse(self, param_list):
        """
        Parses the initialized :attr:`request` to populate :attr:`params` retrieved from the parser.

        Once this method has been called, all expected parameters are guaranteed to exist within :attr`params`.
        Missing query parameters from the :attr:`request` will be set to ``None``.
        All query parameter names will be normalized to *lower* characters for easier retrieval.

        :param param_list: all known query parameters to the service.
        """
        for param_name in param_list:
            self.params[param_name] = self._get_param_value(param_name)
        return self.params

    @abc.abstractmethod
    def _get_param_value(self, param):
        raise NotImplementedError


class OWSGetParser(OWSParser):
    """
    Basically a case-insensitive query string parser.
    """

    def __init__(self, request):
        super(OWSGetParser, self).__init__(request)
        self._params = self._request_params()

    def _request_params(self):
        new_params = {}
        for param in self.request.params:
            new_params[param.lower()] = self.request.params[param].lower()
        return new_params

    def _get_param_value(self, param):
        if param in self._params:
            return self._params[param]
        return None


def lxml_strip_ns(tree):
    for node in tree.iter():
        try:
            has_namespace = node.tag.startswith("{")
        except AttributeError:
            continue  # node.tag is not a string (node is a comment or similar)
        if has_namespace:
            node.tag = node.tag.split("}", 1)[1]


class OWSPostParser(OWSParser):

    def __init__(self, request):
        super(OWSPostParser, self).__init__(request)
        self.document = lxml.etree.fromstring(self.request.body)  # nosec: B410
        lxml_strip_ns(self.document)

    def _get_param_value(self, param):
        if param in self.document.attrib:
            return self.document.attrib[param].lower()
        if param == "request":
            return self.document.tag.lower()
        for section in self.document:
            if param == section.tag.lower():
                return section.text.strip()
        return None


class MultiFormatParser(OWSParser):
    def _get_param_value(self, param):
        return get_multiformat_body(self.request, param, None)
