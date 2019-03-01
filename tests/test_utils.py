#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_utils
----------------------------------

Tests for the various utility operations employed by magpie.
"""

from magpie.api import api_requests as ar, api_except as ax
from magpie.common import get_header, JSON_TYPE
from magpie.definitions.pyramid_definitions import (    # noqa: F401
    asbool,
    Request,
    HTTPInternalServerError,
    HTTPNotAcceptable,
    HTTPBadRequest,
    HTTPOk,
)
from pyramid.testing import DummyRequest
from tests import utils, runner
from typing import TYPE_CHECKING
# noinspection PyDeprecation
from contextlib import nested
import mock
import unittest
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Str  # noqa: F401


@runner.MAGPIE_TEST_UTILS
class TestUtils(unittest.TestCase):
    @staticmethod
    def make_request(request_path_query):
        # type: (Str) -> Request
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

    @runner.MAGPIE_TEST_LOCAL
    def test_proxy_url_direct_request(self):
        magpie_url = 'http://random-host/some-base/path'
        app = utils.get_test_magpie_app({'magpie.url': magpie_url})

        path = '/version'
        resp = utils.test_request(app, 'GET', path)
        utils.check_response_basic_info(resp)
        utils.check_val_equal(resp.request.url, magpie_url + path, "Proxied path should have been auto-resolved.")

    @runner.MAGPIE_TEST_LOCAL
    def test_proxy_url_request_with_multiple_route_url(self):
        """
        Test multiple request routing with fixed 'MAGPIE_URL' within the API application.

        Signin with invalid credentials will call '/signin' followed by sub-request '/signin_internal' and
        finally 'ZigguratSignInBadAuth'. Both '/signin' and 'ZigguratSignInBadAuth' use 'get_multiformat_post'.
        """

        paths = ['/signin', '/signin_internal']

        def mock_get_multiformat_post(*args, **kwargs):
            return get_post_item(*args, p=paths.pop(0), **kwargs)

        def get_post_item(request, name, default=None, p=None):
            utils.check_val_equal(request.url, magpie_url + p, "Proxied path should have been auto-resolved.")
            return request.json.get(name, default)

        magpie_url = 'http://random-host/some-base/path'
        app = utils.get_test_magpie_app({'magpie.url': magpie_url})

        with mock.patch('magpie.api.login.login.get_multiformat_post', side_effect=mock_get_multiformat_post):
            data = {'user_name': 'foo', 'password': 'bar'}
            headers = {'Content-Type': JSON_TYPE, 'Accept': JSON_TYPE}
            resp = utils.test_request(app, 'POST', paths[0], json=data, headers=headers, expect_errors=True)
            utils.check_response_basic_info(resp, expected_code=401)

    @runner.MAGPIE_TEST_LOCAL
    def test_proxy_url_request(self):
        magpie_url = 'http://random-host/some-base/path'
        app = utils.get_test_magpie_app({'magpie.url': magpie_url})

        path = '/version'
        resp = utils.test_request(app, 'GET', path)
        utils.check_response_basic_info(resp)
        utils.check_val_equal(resp.request.url, magpie_url + path, "Proxied path should have been auto-resolved.")

    def test_get_header_split(self):
        headers = {'Content-Type': '{}; charset=UTF-8'.format(JSON_TYPE)}
        for name in ['content_type', 'content-type', 'Content_Type', 'Content-Type', 'CONTENT_TYPE', 'CONTENT-TYPE']:
            for split in [';,', ',;', ';', (',', ';'), [';', ',']]:
                utils.check_val_equal(get_header(name, headers, split=split), JSON_TYPE)

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

    def test_verify_param_proper_verifications(self):
        # with default error
        utils.check_raises(lambda: ax.verify_param('b', paramCompare=['a', 'b'], notIn=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param('x', paramCompare=['a', 'b'], isIn=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param('1', paramCompare=int, ofType=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param('x', paramCompare='x', notEqual=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param('x', paramCompare='y', isEqual=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param(False, isTrue=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param(True, isFalse=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param(None, notNone=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param(1, isNone=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param('', notEmpty=True), HTTPNotAcceptable)
        utils.check_raises(lambda: ax.verify_param('abc', isEmpty=True), HTTPNotAcceptable)

        # with requested error
        utils.check_raises(lambda: ax.verify_param('b', paramCompare=['a', 'b'], notIn=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param('x', paramCompare=['a', 'b'], isIn=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param('1', paramCompare=int, ofType=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param('x', paramCompare='x', notEqual=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param('x', paramCompare='y', isEqual=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(False, isTrue=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(True, isFalse=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(None, notNone=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param(1, isNone=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param('', notEmpty=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)
        utils.check_raises(lambda: ax.verify_param('abc', isEmpty=True,
                                                   httpError=HTTPBadRequest), HTTPBadRequest)

    def test_verify_param_incorrect_usage(self):
        utils.check_raises(lambda: ax.verify_param('b', paramCompare=['a', 'b']), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param('b', paramCompare=['a', 'b'], notIn=None), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param('b', notIn=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param('b', paramCompare=['a', 'b'], notIn=True,
                                                   httpError=HTTPOk), HTTPInternalServerError)

    def test_verify_param_compare_types(self):
        """param and paramCompare must be of same type"""
        utils.check_raises(lambda: ax.verify_param('1', paramCompare=1, isEqual=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param('1', paramCompare=True, isEqual=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param(1, paramCompare='1', isEqual=True), HTTPInternalServerError)
        utils.check_raises(lambda: ax.verify_param(1, paramCompare=True, isEqual=True), HTTPInternalServerError)

        # strings cases handled correctly (no raise)
        utils.check_no_raise(lambda: ax.verify_param('1', paramCompare=u'1', isEqual=True))
