"""
The OWSRequest is based on pywps code:

* https://github.com/geopython/pywps/tree/pywps-3.2/pywps/Parser
* https://github.com/geopython/pywps/blob/master/pywps/app/WPSRequest.py
"""

from magpie.api.requests import get_multiformat_any
from magpie.utils import get_logger, CONTENT_TYPE_JSON, CONTENT_TYPE_PLAIN, CONTENT_TYPE_FORM, is_json_body
from typing import TYPE_CHECKING
# noinspection PyUnresolvedReferences
import lxml.etree

if TYPE_CHECKING:
    from pyramid.request import Request
LOGGER = get_logger(__name__)


def ows_parser_factory(request):
    # type: (Request) -> OWSParser
    """
    Retrieve the appropriate ``OWSRequest`` parser using the ``Content-Type`` header.

    Default to JSON if no ``Content-Type`` is specified or if it is 'text/plain' but can be parsed as JSON. Otherwise,
    use the GET/POST WPS parsers.
    """
    content_type = request.headers.get("Content-Type", None)

    if content_type is None or content_type == CONTENT_TYPE_PLAIN:
        if is_json_body(request.body):
            # default to json when can be parsed as json
            request.content_type = content_type = CONTENT_TYPE_JSON

    if content_type in (CONTENT_TYPE_JSON, CONTENT_TYPE_FORM):
        return MultiFormatParser(request)

    if request.body:
        return WPSPost(request)

    return WPSGet(request)


class OWSParser(object):

    def __init__(self, request):
        self.request = request
        self.params = {}

    def parse(self, param_list):
        for param_name in param_list:
            self.params[param_name] = self._get_param_value(param_name)
        return self.params

    def _get_param_value(self, param):
        raise NotImplementedError


class WPSGet(OWSParser):
    """Basically a case-insensitive query string parser"""

    def __init__(self, request):
        super(WPSGet, self).__init__(request)
        self.all_params = self._request_params()

    def _request_params(self):
        new_params = {}
        for param in self.request.params:
            new_params[param.lower()] = self.request.params[param].lower()
        return new_params

    def _get_param_value(self, param):
        if param in self.all_params:
            return self.all_params[param]
        else:
            return None


def lxml_strip_ns(tree):
    for node in tree.iter():
        try:
            has_namespace = node.tag.startswith("{")
        except AttributeError:
            continue  # node.tag is not a string (node is a comment or similar)
        if has_namespace:
            node.tag = node.tag.split("}", 1)[1]


class WPSPost(OWSParser):

    def __init__(self, request):
        super(WPSPost, self).__init__(request)
        # noinspection PyUnresolvedReferences
        self.document = lxml.etree.fromstring(self.request.body)
        lxml_strip_ns(self.document)

    def _get_param_value(self, param):
        if param in self.document.attrib:
            return self.document.attrib[param].lower()
        elif param == "request":
            return self.document.tag.lower()
        else:
            return None


class MultiFormatParser(OWSParser):
    def _get_param_value(self, param):
        return get_multiformat_any(self.request, param, None)
