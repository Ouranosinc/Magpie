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

from magpie import __meta__, models, owsrequest
from magpie.adapter.magpieowssecurity import OWSAccessForbidden
from magpie.constants import get_constant
from magpie.permissions import Access, Permission, PermissionSet, Scope
from magpie.services import ServiceAccess, ServiceAPI, ServiceTHREDDS, ServiceWPS
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
        assert isinstance(parser, owsrequest.OWSGetParser)

        params = {"test": "something"}
        parser = make_ows_parser(method="GET", content_type=None, params=params, body="")
        assert isinstance(parser, owsrequest.OWSGetParser)
        assert parser.params["test"] == "something"

        body = six.ensure_binary('<?xml version="1.0" encoding="UTF-8"?><Execute/>')    # pylint: disable=C4001
        parser = make_ows_parser(method="POST", content_type=None, params=None, body=body)
        assert isinstance(parser, owsrequest.OWSPostParser)

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
        assert isinstance(parser, owsrequest.OWSGetParser)
        assert parser.params["test"] == "something"

        params = {"test": "something"}
        parser = make_ows_parser(method="PATCH", content_type=None, params=params, body="")
        parser.parse(["test"])
        assert isinstance(parser, owsrequest.OWSGetParser)
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
    @utils.mock_get_settings
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

    def mock_request(self, *args, **kwargs):
        kwargs.update({"cookies": self.test_cookies, "headers": self.test_headers})
        return super(TestServices, self).mock_request(*args, **kwargs)

    @utils.mock_get_settings
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

        svc_name = "unittest-service-api"
        svc_type = ServiceAPI.service_type
        res_type = models.Route.resource_type_name
        res_name = "sub"
        res_kw = {"override_resource_name": res_name, "override_resource_type": res_type}
        utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
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
        rDR = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)      # noqa
        wAR = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)    # noqa
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

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_ServiceTHREDDS_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceTHREDDS` against a mocked `Magpie` adapter for `Twitcher`.

        Validate that both :class:`model.Directory` and :class:`model.File` can be created under :class:`ServiceTHREDDS`
        but that only :class:`model.Directory` then allows nested sub-resources. Resource of type :class:`model.File`
        must correctly indicate a leaf resource.


        Legend::

            r: read     (interpreted as literal filesystem READ)
            w: write    (interpreted as literal filesystem WRITE)
            A: allow
            D: deny
            M: match
            R: recursive

        Permissions Applied::
                                        user            group           effective (reason/importance)
            Service1                    (w-D-M)         (w-A-R)         r-D, w-D  (user > group)
                Directory1              (r-A-R)                         r-A, w-A
                    Directory2                          (r-D-R)         r-D, w-A  (revert user-res1)
                        Directory3      (w-A-R)         (w-D-M)         r-D, w-A  (user > group)
                            File1                       (w-D-M)         r-D, w-D  (match > recursive)
                Directory4                              (r-A-R)         r-A, w-A
                    File2               (w-D-M)                         r-A, w-D
                    Directory5                                          r-A, w-A
                        File3           (r-D-M)                         r-D, w-A
        """
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)

        svc_name = "unittest-service-thredds"
        svc_type = ServiceTHREDDS.service_type
        dir_type = models.Directory.resource_type_name
        file_type = models.File.resource_type_name
        utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
        body = utils.TestSetup.create_TestService(self, override_service_name=svc_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc_id = info["resource_id"]

        def make_res(res_type, index, parent_id):
            res_name = "unittest-{}{}".format(res_type, index)
            res_body = utils.TestSetup.create_TestResource(self, parent_resource_id=parent_id,
                                                           override_resource_type=res_type,
                                                           override_resource_name=res_name)
            res_info = utils.TestSetup.get_ResourceInfo(self, override_body=res_body)
            return res_info["resource_id"], res_name

        # create resources
        dir1_id, dir1_name = make_res(dir_type, 1, svc_id)
        dir2_id, dir2_name = make_res(dir_type, 2, dir1_id)
        dir3_id, dir3_name = make_res(dir_type, 3, dir2_id)
        dir4_id, dir4_name = make_res(dir_type, 4, svc_id)
        dir5_id, dir5_name = make_res(dir_type, 5, dir4_id)
        file1_id, file1_name = make_res(file_type, 1, dir3_id)
        file2_id, file2_name = make_res(file_type, 2, dir4_id)
        file3_id, file3_name = make_res(file_type, 3, dir5_id)

        # assign permissions
        rAR = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)     # noqa
        rDR = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)      # noqa
        rDM = PermissionSet(Permission.READ, Access.DENY, Scope.MATCH)          # noqa
        wAR = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)    # noqa
        wDM = PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH)         # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc_id, override_permission=wAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=dir1_id, override_permission=rAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=dir2_id, override_permission=rDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=dir3_id, override_permission=wAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=dir3_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=file1_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=dir4_id, override_permission=rAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=file2_id, override_permission=wDM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=file3_id, override_permission=rDM)

        raise NotImplementedError  # FIXME validation of ACL

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_ServiceNCWMS2_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceNCWMS2` against a mocked `Magpie` adapter for `Twitcher`.
        """
        raise NotImplementedError  # FIXME

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_ServiceGeoserverWMS_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceGeoserverWMS` against a mocked `Magpie` adapter for `Twitcher`.


        """

        #   /geoserver/wms?request=getcapabilities (get all workspaces)
        #   /geoserver/WATERSHED/wms?request=getcapabilities (only for the workspace in the path)
        #   /geoserver/WATERSHED/wms?layers=WATERSHED:BV_1NS&request=getmap
        #   /geoserver/wms?layers=WATERERSHED:BV1_NS&request=getmap
        raise NotImplementedError  # FIXME

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_ServiceWFS_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceWFS` against a mocked `Magpie` adapter for `Twitcher`.
        """
        raise NotImplementedError  # FIXME

    @utils.mock_get_settings
    def test_ServiceWPS_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceWFS` against a mocked `Magpie` adapter for `Twitcher`.

        Legend::

            g: GetCapabilities (*)
            d: DescribeProcess
            e: Execute
            A: allow
            D: deny
            M: match
            R: recursive

        Permissions Applied::
                                        user        group               effective
            Service1                    (g-A-R)                         g-A,    d-D, e-D
                Process1                (e-A-M)     (d-A-M)             g-A,    d-A, e-A
            Service2                    (d-A-R)     (g-A-R)             g-A,    d-A, e-D
                Process2                            (g-D-M), (e-A-M)    g-A(*), d-A, e-A
                Process3                (e-D-M)                         g-A,    d-A, e-D

        .. note:: (*)
            All ``GetCapabilities`` requests completely ignore ``identifier`` query parameter by resolving immediately
            to the parent WPS Service since no Process applies in this case.

            For this reason, although ``(g-D-M)`` is applied on ``Process2``, Process ``identifier`` does not take place
            in ``GetCapabilities``. Therefore, the ACL is immediately resolved with the parent ``Service2`` permission
            of ``(g-A-R)`` which grants effective access.
        """
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)

        # create services
        wps1_name = "unittest-service-wps-1"
        wps2_name = "unittest-service-wps-2"
        svc_type = ServiceWPS.service_type
        proc_type = models.Process.resource_type_name
        body = utils.TestSetup.create_TestService(self, override_service_name=wps1_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        wps1_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=wps2_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        wps2_id = info["resource_id"]

        # create processes
        proc1_name = "unittest-process-1"
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=wps1_id,
                                                   override_resource_name=proc1_name,
                                                   override_resource_type=proc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        proc1_id = info["resource_id"]
        proc2_name = "unittest-process-2"
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=wps2_id,
                                                   override_resource_name=proc2_name,
                                                   override_resource_type=proc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        proc2_id = info["resource_id"]
        proc3_name = "unittest-process-3"
        body = utils.TestSetup.create_TestResource(self, parent_resource_id=wps2_id,
                                                   override_resource_name=proc3_name,
                                                   override_resource_type=proc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        proc3_id = info["resource_id"]

        # assign permissions
        gAR = PermissionSet(Permission.GET_CAPABILITIES, Access.ALLOW, Scope.RECURSIVE)     # noqa
        dAM = PermissionSet(Permission.DESCRIBE_PROCESS, Access.ALLOW, Scope.MATCH)         # noqa
        dAR = PermissionSet(Permission.DESCRIBE_PROCESS, Access.ALLOW, Scope.RECURSIVE)     # noqa
        eAM = PermissionSet(Permission.EXECUTE, Access.ALLOW, Scope.MATCH)                  # noqa
        eDM = PermissionSet(Permission.EXECUTE, Access.DENY, Scope.MATCH)                   # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=wps1_id, override_permission=gAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=proc1_id, override_permission=eAM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=proc1_id, override_permission=dAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=wps2_id, override_permission=dAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=wps2_id, override_permission=gAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=proc2_id, override_permission=eAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=proc3_id, override_permission=eDM)

        # login test user for which the permissions were set
        utils.check_or_try_logout_user(self)
        cred = utils.check_or_try_login_user(self, username=self.test_user_name, password=self.test_user_name)
        self.test_headers, self.test_cookies = cred

        # note:
        #   Following requests use various 'service' and 'request' values that do not necessarily match the exact format
        #   of corresponding enums to validate the request query parameters are parsed correctly with combinations that
        #   are actually handled by the real WPS service.

        # Service1 calls
        path = "/ows/proxy/{}".format(wps1_name)
        params = {"service": "WPS", "request": "GetCapabilities"}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "DescribeProcess"}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)
        params = {"service": "WPS", "request": "EXECUTE"}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

        # Process1 calls
        path = "/ows/proxy/{}".format(wps1_name)
        params = {"service": "WPS", "request": "GetCapabilities", "identifier": proc1_name}  # see docstring notes
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "DescribeProcess", "identifier": proc1_name}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "EXECUTE", "identifier": proc1_name}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))

        # Service2 calls
        path = "/ows/proxy/{}".format(wps2_name)
        params = {"service": "WPS", "request": "GetCapabilities"}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "DescribeProcess"}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "EXECUTE"}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

        # Process2 calls
        path = "/ows/proxy/{}".format(wps2_name)
        params = {"service": "WPS", "request": "GETCAPABILITIES", "identifier": proc2_name}  # see docstring notes
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "DescribeProcess", "identifier": proc2_name}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "EXECUTE", "identifier": proc2_name}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))

        # Process3 calls
        path = "/ows/proxy/{}".format(wps2_name)
        params = {"service": "WPS", "request": "GETCAPABILITIES", "identifier": proc3_name}  # see docstring notes
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "DescribeProcess", "identifier": proc3_name}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_no_raise(lambda: self.ows.check_request(req))
        params = {"service": "WPS", "request": "EXECUTE", "identifier": proc3_name}
        req = self.mock_request(path, method="GET", params=params)
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

    @utils.mock_get_settings
    def test_ServiceAccess_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceAccess` against a mocked `Magpie` adapter for `Twitcher`.

        The :class:`ServiceAccess` implementation works as an all-or-nothing endpoint (similar to `Twitcher`'s default
        proxy behaviour when :class:`magpie.adapter.MagpieAdapter` is not employed).

        Validate that the service does not allow creation of children resource and that access is granted or refused
        according to :class:`Access` modifiers of the resolved permission. The :class:`Scope` modifier has no effect
        due to forbidden creation of children resources.

        Legend::

            a: access       (permission `name`, not to be confused with `access` permission modifier)
            A: allow
            D: deny
            M: match        (doesn't matter because service always directly referenced)
            R: recursive    (doesn't matter because service always directly referenced)

        Permissions Applied::
                                        user        group               effective (reason)
            Service1                    (a-A-R)                         a-A
            Service2                                (a-A-M)             a-A
            Service3                    (a-D-M)                         a-D
            Service4                                (a-D-R)             a-D
            Service5                    (a-A-R)     (a-D-M)             a-A (user > group)
            Service6                                                    a-D (nothing defaults like explicit deny)
        """

        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestUser(self)

        # create services
        svc_type = ServiceAccess.service_type
        svc1_name = "unittest-service-access-1"
        svc2_name = "unittest-service-access-2"
        svc3_name = "unittest-service-access-3"
        svc4_name = "unittest-service-access-4"
        svc5_name = "unittest-service-access-5"
        svc6_name = "unittest-service-access-6"
        for svc_name in [svc1_name, svc2_name, svc3_name, svc4_name, svc5_name, svc6_name]:
            utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
        body = utils.TestSetup.create_TestService(self, override_service_name=svc1_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc1_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=svc2_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc2_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=svc3_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc3_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=svc4_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc4_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=svc5_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc5_id = info["resource_id"]
        utils.TestSetup.create_TestService(self, override_service_name=svc6_name, override_service_type=svc_type)

        # validate forbidden child resource creation
        path = "/services/{}/resources".format(svc1_name)
        data = {"resource_type": "route", "resource_name": "unittest-service-access-forbidden-child-resource"}
        resp = utils.test_request(self, "POST", path=path, json=data, expect_errors=True,
                                  headers=self.json_headers, cookies=self.cookies)
        utils.check_response_basic_info(resp, 403, expected_method="POST")

        # assign permissions on service
        aAR = PermissionSet(Permission.ACCESS, Access.ALLOW, Scope.RECURSIVE)   # noqa
        aAM = PermissionSet(Permission.ACCESS, Access.ALLOW, Scope.MATCH)       # noqa
        aDR = PermissionSet(Permission.ACCESS, Access.DENY, Scope.RECURSIVE)    # noqa
        aDM = PermissionSet(Permission.ACCESS, Access.DENY, Scope.MATCH)        # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc1_id, override_permission=aAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc2_id, override_permission=aAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc3_id, override_permission=aDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc4_id, override_permission=aDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc5_id, override_permission=aAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc5_id, override_permission=aDM)

        # login test user for which the permissions were set
        utils.check_or_try_logout_user(self)
        cred = utils.check_or_try_login_user(self, username=self.test_user_name, password=self.test_user_name)
        self.test_headers, self.test_cookies = cred

        # services calls
        req = self.mock_request("/ows/proxy/{}".format(svc1_name), method="GET")
        utils.check_no_raise(lambda: self.ows.check_request(req))
        req = self.mock_request("/ows/proxy/{}".format(svc2_name), method="GET")
        utils.check_no_raise(lambda: self.ows.check_request(req))
        req = self.mock_request("/ows/proxy/{}".format(svc3_name), method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)
        req = self.mock_request("/ows/proxy/{}".format(svc4_name), method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)
        req = self.mock_request("/ows/proxy/{}".format(svc5_name), method="GET")
        utils.check_no_raise(lambda: self.ows.check_request(req))
        req = self.mock_request("/ows/proxy/{}".format(svc6_name), method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

    @unittest.skip("impl")
    @pytest.mark.skip
    def test_ServiceADES_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceADES` against a mocked `Magpie` adapter for `Twitcher`.

        .. note::
            Service of type :class:`ServiceADES` is a combination of :class:`ServiceAPI` and :class:`ServiceWPS` with
            corresponding resources accessed through different endpoints and formats.
        """
        raise NotImplementedError  # FIXME: see https://github.com/Ouranosinc/Magpie/issues/360
