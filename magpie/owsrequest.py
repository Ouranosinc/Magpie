"""
The OWSRequest is based on pywps code:

* https://github.com/geopython/pywps/tree/pywps-3.2/pywps/Parser
* https://github.com/geopython/pywps/blob/master/pywps/app/WPSRequest.py
"""

from magpie.api.api_except import raise_http
from magpie.common import get_logger
from pyramid.httpexceptions import HTTPMethodNotAllowed
from requests import Request
import lxml.etree
import json
LOGGER = get_logger(__name__)


def ows_parser_factory(request):
    # type: (Request) -> OWSParser
    """
    Retrieve the appropriate OWS Request parser using the Content-Type header.
    Default to JSON if no Content-Type is specified or if it is 'text/plain' but can be parsed as JSON.
    Otherwise, use the GET/POST WPS parsers.
    """
    content_type = request.headers.get('Content-Type', 'application/json')
    if content_type == 'text/plain':
        try:
            # noinspection PyUnresolvedReferences
            if request.body:
                # raises if parsing fails
                # noinspection PyUnresolvedReferences
                json.loads(request.body)
            content_type = 'application/json'
        except ValueError:
            pass
    if content_type == 'application/json':
        return JSONParser(request)
    else:
        if request.method == 'GET':
            return WPSGet(request)
        elif request.method == 'POST':
            return WPSPost(request)

    # method not supported, raise using the specified content type header
    raise_http(httpError=HTTPMethodNotAllowed, contentType=content_type,
               detail="Method not implemented by Magpie OWSParser.")


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

    def _request_params(self):
        new_params = {}
        for param in self.request.params:
            new_params[param.lower()] = self.request.params[param].lower()
        return new_params

    def __init__(self, request):
        super(WPSGet, self).__init__(request)
        self.all_params = self._request_params()

    def _get_param_value(self, param):
        if param in self.all_params:
            return self.all_params[param]
        else:
            return None


def lxml_strip_ns(tree):
    for node in tree.iter():
        try:
            has_namespace = node.tag.startswith('{')
        except AttributeError:
            continue  # node.tag is not a string (node is a comment or similar)
        if has_namespace:
            node.tag = node.tag.split('}', 1)[1]


class WPSPost(OWSParser):

    def __init__(self, request):
        super(WPSPost, self).__init__(request)
        self.document = lxml.etree.fromstring(self.request.body)
        lxml_strip_ns(self.document)

    def _get_param_value(self, param):
        if param in self.document.attrib:
            return self.document.attrib[param].lower()
        elif param == 'request':
            return self.document.tag.lower()
        else:
            return None


class JSONParser(OWSParser):
    def _get_param_value(self, param):
        param = param or ''  # in case None
        return self.params.get(param.lower(), '').lower()
