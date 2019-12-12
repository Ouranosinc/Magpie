#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_services
----------------------------------

Tests for the services implementations magpie.
"""
import json
import unittest

import six
from pyramid.testing import DummyRequest

from magpie import owsrequest
from magpie.definitions.typedefs import TYPE_CHECKING
from magpie.utils import CONTENT_TYPE_FORM, CONTENT_TYPE_JSON, CONTENT_TYPE_PLAIN
from tests import runner

if TYPE_CHECKING:
    from magpie.definitions.typedefs import Dict, Optional, Str  # noqa: F401


def make_ows_parser(method='GET', content_type=None, params=None, body=''):
    # type: (Str, Optional[Str], Optional[Dict[Str, Str]], Optional[Str]) -> owsrequest.OWSParser
    """
    Makes an :class:`owsrequest.OWSParser` from a :class:`DummyRequest`
    definition with provided parameters for testing.
    """
    request = DummyRequest(params=params)
    request.method = method
    request.content_type = content_type
    if content_type:
        request.headers["Content-Type"] = content_type
    request.body = body

    try:
        if body:
            # set missing DummyRequest.json attribute
            request.json = json.loads(body)
    except (TypeError, ValueError):
        pass

    if params is None:
        parse_params = []
    else:
        parse_params = params.keys()

    parser = owsrequest.ows_parser_factory(request)  # type: ignore # noqa
    parser.parse(parse_params)
    return parser


@runner.MAGPIE_TEST_SERVICES
@runner.MAGPIE_TEST_LOCAL
class TestServices(unittest.TestCase):
    def test_ows_parser_factory(self):
        parser = make_ows_parser(method="GET", content_type=None, params=None, body='')
        assert isinstance(parser, owsrequest.WPSGet)

        params = {"test": "something"}
        parser = make_ows_parser(method="GET", content_type=None, params=params, body='')
        assert isinstance(parser, owsrequest.WPSGet)
        assert parser.params["test"] == "something"

        body = six.ensure_binary('<?xml version="1.0" encoding="UTF-8"?><Execute/>')
        parser = make_ows_parser(method="POST", content_type=None, params=None, body=body)
        assert isinstance(parser, owsrequest.WPSPost)

        body = '{"test": "something"}'
        parser = make_ows_parser(method="POST", content_type=None, params=None, body=body)
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.MultiFormatParser)
        assert parser.params["test"] == "something"

        body = '{"test": "something"}'
        parser = make_ows_parser(method="POST", content_type=CONTENT_TYPE_PLAIN, params=None, body=body)
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.MultiFormatParser)
        assert parser.params["test"] == "something"

        params = {"test": "something"}
        parser = make_ows_parser(method="POST", content_type=CONTENT_TYPE_FORM, params=params, body='')
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.MultiFormatParser)
        assert parser.params["test"] == "something"

        params = {"test": "something"}
        parser = make_ows_parser(method="DELETE", content_type=None, params=params, body='')
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.WPSGet)
        assert parser.params["test"] == "something"

        params = {"test": "something"}
        parser = make_ows_parser(method="PUT", content_type=None, params=params, body='')
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.WPSGet)
        assert parser.params["test"] == "something"

        body = '{"test": "something"}'
        parser = make_ows_parser(method="PUT", content_type=CONTENT_TYPE_JSON, params=None, body=body)
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.MultiFormatParser)
        assert parser.params["test"] == "something"
