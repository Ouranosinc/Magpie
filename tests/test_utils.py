#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_utils
----------------------------------

Tests for the various utility operations employed by magpie.
"""

from magpie.api import api_requests as ar
from magpie.definitions.pyramid_definitions import asbool, Request
from magpie.definitions.typedefs import AnyStr
from pyramid.testing import DummyRequest
from tests import utils, runner
import unittest


@runner.MAGPIE_TEST_UTILS
class TestUtils(unittest.TestCase):
    @staticmethod
    def make_request(request_path_query):
        # type: (AnyStr) -> Request
        parts = request_path_query.split('?')
        path = parts[0]
        query = dict()
        if len(parts) > 1:
            for q in parts[1:]:
                k, v = q.split('=')
                query[k] = v
        # noinspection PyTypeChecker
        return DummyRequest(path=path, params=query)

    @classmethod
    def setUpClass(cls):
        pass

    def test_get_query_param(self):
        r = self.make_request('/some/path')
        v = ar.get_query_param(r, 'value')
        utils.check_val_equal(v, None)

        r = self.make_request('/some/path?other=test')
        v = ar.get_query_param(r, 'value')
        utils.check_val_equal(v, None)

        r = self.make_request('/some/path?other=test')
        v = ar.get_query_param(r, 'value', True)
        utils.check_val_equal(v, True)

        r = self.make_request('/some/path?value=test')
        v = ar.get_query_param(r, 'value', True)
        utils.check_val_equal(v, 'test')

        r = self.make_request('/some/path?query=value')
        v = ar.get_query_param(r, 'query')
        utils.check_val_equal(v, 'value')

        r = self.make_request('/some/path?QUERY=VALUE')
        v = ar.get_query_param(r, 'query')
        utils.check_val_equal(v, 'VALUE')

        r = self.make_request('/some/path?QUERY=VALUE')
        v = asbool(ar.get_query_param(r, 'query'))
        utils.check_val_equal(v, False)

        r = self.make_request('/some/path?Query=TRUE')
        v = asbool(ar.get_query_param(r, 'query'))
        utils.check_val_equal(v, True)
