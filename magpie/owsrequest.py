"""
The OWSRequest is based on pywps code:

* https://github.com/geopython/pywps/tree/pywps-3.2/pywps/Parser
* https://github.com/geopython/pywps/blob/master/pywps/app/WPSRequest.py
"""

import lxml.etree

from pyramid.httpexceptions import HTTPBadRequest


import logging
logger = logging.getLogger(__name__)

def ows_parser_factory(request):
    if request.method == 'GET':
        return Get(request)
    elif request.method == 'POST':
        return Post(request)
    else:
        raise HTTPBadRequest()


class OWSParser(object):

    def __init__(self, request):
        self.request = request
        self.params = {}

    def parse(self, param_list):
        for param_name in param_list:
            self.params[param_name] = self._get_param_value(param_name)
        return self.params

    def _get_param_value(self):
        raise NotImplementedError


class Get(OWSParser):

    def _request_params(self):
        new_params = {}
        for param in self.request.params:
            # new_params[param.lower()] = self.request.params.getone(param)
            new_params[param.lower()] = self.request.params[param].lower()
        return new_params

    def __init__(self, request):
        super(Get, self).__init__(request)
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


class Post(OWSParser):

    def __init__(self, request):
        super(Post, self).__init__(request)
        try:
            self.document = lxml.etree.fromstring(self.request.body)
            lxml_strip_ns(self.document)
        except Exception as e:
            raise Exception(e.message)

    def _get_param_value(self, param):
        if param in self.document.attrib:
            return self.document.attrib[param].lower()
        elif param == 'request':
            return self.document.tag.lower()
        else:
            return None
