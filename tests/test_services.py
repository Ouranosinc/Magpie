#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_services
----------------------------------

Tests for the services implementations magpie.
"""
import unittest
from typing import TYPE_CHECKING

import pytest
import six

from magpie import __meta__, owsrequest
from magpie.adapter.magpieowssecurity import OWSAccessForbidden
from magpie.constants import get_constant
from magpie.permissions import Access, Permission, PermissionSet, Scope
from magpie.services import ServiceAPI
from magpie.utils import CONTENT_TYPE_FORM, CONTENT_TYPE_JSON, CONTENT_TYPE_PLAIN
from tests import interfaces as ti, runner, utils

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Dict, Optional

    from magpie.typedefs import Str


def make_ows_parser(method="GET", content_type=None, params=None, body=""):
    # type: (Str, Optional[Str], Optional[Dict[Str, Str]], Optional[Str]) -> owsrequest.OWSParser
    """
    Makes an :class:`owsrequest.OWSParser` from mocked request definition with provided parameters for testing.
    """
    request = utils.mock_request("", params=params, body=body, method=method, content_type=content_type)
    if params is None:
        parse_params = []
    else:
        parse_params = params.keys()

    parser = owsrequest.ows_parser_factory(request)
    parser.parse(parse_params)
    return parser


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_SERVICES
class TestOWSParser(unittest.TestCase):
    def test_ows_parser_factory(self):  # noqa: R0201
        parser = make_ows_parser(method="GET", content_type=None, params=None, body="")
        assert isinstance(parser, owsrequest.WPSGet)

        params = {"test": "something"}
        parser = make_ows_parser(method="GET", content_type=None, params=params, body="")
        assert isinstance(parser, owsrequest.WPSGet)
        assert parser.params["test"] == "something"

        body = six.ensure_binary('<?xml version="1.0" encoding="UTF-8"?><Execute/>')    # pylint: disable=C4001
        parser = make_ows_parser(method="POST", content_type=None, params=None, body=body)
        assert isinstance(parser, owsrequest.WPSPost)

        body = '{"test": "something"}'  # pylint: disable=C4001
        parser = make_ows_parser(method="POST", content_type=None, params=None, body=body)
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.MultiFormatParser)
        assert parser.params["test"] == "something"

        body = '{"test": "something"}'  # pylint: disable=C4001
        parser = make_ows_parser(method="POST", content_type=CONTENT_TYPE_PLAIN, params=None, body=body)
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.MultiFormatParser)
        assert parser.params["test"] == "something"

        params = {"test": "something"}
        parser = make_ows_parser(method="POST", content_type=CONTENT_TYPE_FORM, params=params, body="")
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.MultiFormatParser)
        assert parser.params["test"] == "something"

        params = {"test": "something"}
        parser = make_ows_parser(method="DELETE", content_type=None, params=params, body="")
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.WPSGet)
        assert parser.params["test"] == "something"

        params = {"test": "something"}
        parser = make_ows_parser(method="PATCH", content_type=None, params=params, body="")
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.WPSGet)
        assert parser.params["test"] == "something"

        body = '{"test": "something"}'  # pylint: disable=C4001
        parser = make_ows_parser(method="PATCH", content_type=CONTENT_TYPE_JSON, params=None, body=body)
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.MultiFormatParser)
        assert parser.params["test"] == "something"


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_SERVICES
@runner.MAGPIE_TEST_FUNCTIONAL
class TestServices(ti.SetupMagpieAdapter, ti.AdminTestCase, ti.BaseTestCase):
    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.version = __meta__.__version__
        cls.app = utils.get_test_magpie_app(cls.settings)
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.settings = cls.app.app.registry.settings
        ti.SetupMagpieAdapter.setup(cls.settings)

        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.setup_admin()
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd, use_ui_form_submit=True)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.check_requirements()

        # following will be wiped on setup
        cls.test_user_name = "unittest-service-user"
        cls.test_group_name = "unittest-service-group"
        cls.test_service_name_api = "unittest-service-api"

    def setUp(self):
        super(TestServices, self).setUp()
        utils.TestSetup.delete_TestService(self, override_service_name=self.test_service_name_api)

    def mock_request(self, *args, **kwargs):
        kwargs.update({"cookies": self.test_cookies, "headers": self.test_headers})
        return super(TestServices, self).mock_request(*args, **kwargs)

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_unauthenticated_service_blocked(self):
        """
        Validate missing authentication token blocks access to the service if not publicly accessible.
        """
        raise NotImplementedError  # FIXME

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_unauthenticated_resource_allowed(self):
        """
        Validate granted access to a resource specified as publicly accessible even without any authentication token.
        """
        raise NotImplementedError  # FIXME

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_unknown_service(self):
        """
        Validate that unknown service-name is handled correctly.
        """
        raise NotImplementedError  # FIXME

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_unknown_resource_under_service(self):
        """
        Evaluate use-case where requested resource when parsing the request corresponds to non-existing element.

        If the targeted resource does not exist in database, `Magpie` should still allow access if its closest
        available parent permission results into Allow/Recursive.

        If the closest parent permission permission is either Match-scoped or explicit Deny, access should be refused.
        """
        raise NotImplementedError  # FIXME

    def test_ServiceAPI_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceAPI` against a mocked `Magpie` adapter for `Twitcher`.

        Legend::

            r: read     (HTTP HEAD/GET for ServiceAPI)
            w: write    (all other HTTP methods)
            A: allow
            D: deny
            M: match
            R: recursive

        Permissions Applied::
                                        user            group           effective (reason/importance)
            Service1                    (w-D-M)         (w-A-R)         r-D, w-D  (user > group)
                Resource1               (r-A-R)                         r-A, w-A
                    Resource2                           (r-D-R)         r-D, w-A  (revert user-res1)
                        Resource3       (w-A-R)         (w-D-M)         r-D, w-A  (user > group)
                            Resource4                   (w-D-M)         r-D, w-D  (match > recursive)
        """
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)

        svc_name = self.test_service_name_api
        svc_type = ServiceAPI.service_type
        res_type = ServiceAPI.resource_types[0].resource_type_name
        res_name = "sub"
        res_kw = {"override_resource_name": res_name, "override_resource_type": res_type}
        body = utils.TestSetup.create_TestService(self, override_service_name=svc_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=svc_id, **res_kw)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res1_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res1_id, **res_kw)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res2_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res2_id, **res_kw)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res3_id = info["resource_id"]
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=res3_id, **res_kw)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        res4_id = info["resource_id"]

        # setup permissions
        rAR = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)     # noqa
        rAM = PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH)         # noqa
        rDR = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)      # noqa
        rDM = PermissionSet(Permission.READ, Access.DENY, Scope.MATCH)          # noqa
        wAR = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)    # noqa
        wAM = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.MATCH)        # noqa
        wDR = PermissionSet(Permission.WRITE, Access.DENY, Scope.RECURSIVE)     # noqa
        wDM = PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH)         # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc_id, override_permission=wAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res1_id, override_permission=rAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res2_id, override_permission=rDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res3_id, override_permission=wAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res3_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res4_id, override_permission=wDM)

        # login test user for which the permissions were set
        utils.check_or_try_logout_user(self)
        cred = utils.check_or_try_login_user(self, username=self.test_user_name, password=self.test_user_name)
        self.test_headers, self.test_cookies = cred

        # Service1 direct call
        path = "/ows/proxy/{}".format(svc_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)
        req = self.mock_request(path, method="POST")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

        # Service1/Resource1
        path = "/ows/proxy/{}/{}".format(svc_name, res_name)
        req = self.mock_request(path, method="GET")
        utils.check_no_raise(lambda: self.ows.check_request(req))
        req = self.mock_request(path, method="POST")
        utils.check_no_raise(lambda: self.ows.check_request(req))

        # Service1/Resource1/Resource2
        path = "/ows/proxy/{}/{}/{}".format(svc_name, res_name, res_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)
        req = self.mock_request(path, method="POST")
        utils.check_no_raise(lambda: self.ows.check_request(req))

        # Service1/Resource1/Resource2/Resource3
        path = "/ows/proxy/{}/{}/{}/{}".format(svc_name, res_name, res_name, res_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)
        req = self.mock_request(path, method="POST")
        utils.check_no_raise(lambda: self.ows.check_request(req))

        # Service1/Resource1/Resource2/Resource3/Resource4
        path = "/ows/proxy/{}/{}/{}/{}/{}".format(svc_name, res_name, res_name, res_name, res_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)
        req = self.mock_request(path, method="POST")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

        # login with admin user, validate full access granted even if no explicit permissions was set admins
        utils.check_or_try_logout_user(self)
        cred = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        self.test_headers, self.test_cookies = cred
        for res_count in range(0, 5):
            path = "/ows/proxy/{}".format(svc_name) + res_count * "/{}".format(res_name)
            for method in ["GET", "POST", "PUT", "DELETE"]:
                req = self.mock_request(path, method=method)
                utils.check_no_raise(lambda: self.ows.check_request(req))
