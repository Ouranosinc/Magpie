#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_services
----------------------------------

Tests for the services implementations magpie.
"""
import inspect
import itertools
import unittest
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

import mock
import pytest
import six
from sqlalchemy import inspect as sa_inspect

from magpie import __meta__, models, owsrequest
from magpie.constants import get_constant
from magpie.permissions import Access, Permission, PermissionSet, PermissionType, Scope
from magpie.services import (
    ServiceAccess,
    ServiceAPI,
    ServiceGeoserver,
    ServiceGeoserverWMS,
    ServiceInterface,
    ServiceTHREDDS,
    ServiceWPS
)
from magpie.utils import CONTENT_TYPE_FORM, CONTENT_TYPE_JSON, CONTENT_TYPE_TXT_XML
from tests import interfaces as ti
from tests import runner, utils

if six.PY3:
    from magpie.adapter.magpieowssecurity import OWSAccessForbidden  # noqa  # defined via Twitcher

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Dict, Optional, Tuple, Union

    from magpie.typedefs import JSON, Str


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


@unittest.skipIf(six.PY2, "Unsupported Twitcher for MagpieAdapter in Python 2")
@pytest.mark.skipif(six.PY2, reason="Unsupported Twitcher for MagpieAdapter in Python 2")
@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_SERVICES
class TestOWSParser(unittest.TestCase):
    """
    Validate operations of :mod:`magpie.owsrequest` that is employed by multiple :term:`OWS`-based service
    implementations.
    """

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
        parser = make_ows_parser(method="POST", content_type=CONTENT_TYPE_JSON, params=None, body=body)
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
class TestServices(ti.SetupMagpieAdapter, ti.UserTestCase, ti.BaseTestCase):
    """
    Test request parsing and :term:`ACL` resolution against resource permissions for various service implementations.
    """
    # pylint: disable=C0103,invalid-name
    __test__ = True
    test_headers = None
    test_cookies = None

    @classmethod
    @utils.mocked_get_settings
    def setUpClass(cls):
        cls.version = __meta__.__version__
        cls.app = utils.get_test_magpie_app()
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.setup_admin()

        # following will be wiped on setup
        cls.test_user_name = "unittest-service-user"
        cls.test_group_name = "unittest-service-group"

    @utils.mocked_get_settings
    def setUp(self):
        ti.UserTestCase.setUp(self)
        self.setup_adapter()
        self.cookies = None
        self.headers, self.cookies = utils.check_or_try_login_user(self, self.usr, self.pwd, use_ui_form_submit=True)
        self.require = "cannot run tests without logged in user with '{}' permissions".format(self.grp)
        self.login_admin()

    def make_resource(self, resource_type, parent_id, index="", resource_name_prefix=""):
        # type: (Str, int, Union[int, Str], Str) -> Tuple[int, Str]
        if not resource_name_prefix:
            resource_name_prefix = "unittest-" + resource_type
        res_name = "{}{}".format(resource_name_prefix, index)
        res_body = utils.TestSetup.create_TestResource(self, parent_resource_id=parent_id,
                                                       override_resource_type=resource_type,
                                                       override_resource_name=res_name)
        res_info = utils.TestSetup.get_ResourceInfo(self, override_body=res_body)
        return res_info["resource_id"], res_name

    @utils.mocked_get_settings
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
                                              | user            | group           | effective (reason/importance)
            ==================================+=================+=================+====================================
            Service1                          |         (w-D-M) |         (w-A-R) | r-D, w-D  (user > group)
                Resource1                     |                 | (r-A-R)         | r-A, w-A
                    Resource2                 | (r-D-R)         |                 | r-D, w-A  (revert user-res1)
                        Resource3             |         (w-A-R) |         (w-D-M) | r-D, w-A  (user > group)
                            Resource4         |         (w-D-M) |                 | r-D, w-D  (match > recursive)
                                Resource5 (*) | [-----n/a-----] | [-----n/a-----] | r-D, w-A  (see note below)

        .. note:: (*)
            Last ``Resource5`` doesn't exist, but recursive access should be granted/refused from *closest* parent
            resource *recursive* permission that could be found. In this case ``Resource2`` for ``read`` permission
            and ``Resource3`` for ``write`` permission.

        .. versionchanged:: 3.5
            User and Group permissions for ``Resource1`` and ``Resource2`` have been swapped since new priorities make
            :term:`Direct Permissions <Direct Permission>` more important than
            :term:`Inherited Permissions <Inherited Permission>`. The :attr:`Access.DENY` was not being reverted with
            original definitions that assumed them to be of equal importance, and therefore plain ``DENY > ALLOW`` was
            working. Permission on ``Resource4`` was moved from Group to User for the same reason.
        """
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
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res1_id, override_permission=rAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res2_id, override_permission=rDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res3_id, override_permission=wAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res3_id, override_permission=wDM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res4_id, override_permission=wDM)

        # login test user for which the permissions were set
        self.login_test_user()

        # Service1 direct call
        path = "/ows/proxy/{}".format(svc_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [GET, {}]".format(path))
        req = self.mock_request(path, method="POST")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [POST, {}]".format(path))

        # Service1/Resource1
        path = "/ows/proxy/{svc}/{res}".format(svc=svc_name, res=res_name)
        req = self.mock_request(path, method="GET")
        utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [GET, {}]".format(path))
        req = self.mock_request(path, method="POST")
        utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [POST, {}]".format(path))

        # Service1/Resource1/Resource2
        path = "/ows/proxy/{svc}/{res}/{res}".format(svc=svc_name, res=res_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [GET, {}]".format(path))
        req = self.mock_request(path, method="POST")
        utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [POST, {}]".format(path))

        # Service1/Resource1/Resource2/Resource3
        path = "/ows/proxy/{svc}/{res}/{res}/{res}".format(svc=svc_name, res=res_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [GET, {}]".format(path))
        req = self.mock_request(path, method="POST")
        utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [POST, {}]".format(path))

        # Service1/Resource1/Resource2/Resource3/Resource4
        path = "/ows/proxy/{svc}/{res}/{res}/{res}/{res}".format(svc=svc_name, res=res_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [GET, {}]".format(path))
        req = self.mock_request(path, method="POST")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [POST, {}]".format(path))

        # Service1/Resource1/Resource2/Resource3/Resource4/Resource5 (last resource does not exist)
        path = "/ows/proxy/{svc}/{res}/{res}/{res}/{res}/{res}".format(svc=svc_name, res=res_name)
        req = self.mock_request(path, method="GET")
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg="Using [GET, {}]".format(path))
        req = self.mock_request(path, method="POST")
        utils.check_no_raise(lambda: self.ows.check_request(req), msg="Using [POST, {}]".format(path))

        # login with admin user, validate full access granted even if no explicit permissions was set admins
        utils.check_or_try_logout_user(self)
        cred = utils.check_or_try_login_user(self, username=self.usr, password=self.pwd)
        self.test_headers, self.test_cookies = cred
        for res_count in range(0, 5):
            path = "/ows/proxy/{}".format(svc_name) + res_count * "/{}".format(res_name)
            for method in ["GET", "POST", "PUT", "DELETE"]:
                req = self.mock_request(path, method=method)
                msg = "Using [{}, {}]".format(method, path)
                utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)

    @utils.mocked_get_settings
    def test_ServiceTHREDDS_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceTHREDDS` against a mocked `Magpie` adapter for `Twitcher`.

        Validate that both :class:`model.Directory` and :class:`model.File` can be created under :class:`ServiceTHREDDS`
        but that only :class:`model.Directory` then allows nested sub-resources. Resource of type :class:`model.File`
        must correctly indicate a leaf resource.

        Validate access of created resources. All :class:`model.File` resources refer to a common data representation
        of a file with ``.nc`` extension, where any additional extension refer to the same element (eg: ``.nc.dds``).
        When the final element is ``catalog.html``, it must be parsed as the parent :class:`model.Directory` since that
        path refers to the HTML page with UI rendering of the contents of the directory.

        Legend::

            b: browse   (access of resource *metadata*, both for File information and Directory listing)
            r: read     (interpreted as literal file system READ of *data*, effective resolution valid only on File)
            w: write    (unused by ACL resolution)
            A: allow
            D: deny
            M: match
            R: recursive

        Permissions Applied::

                               | user                    | group                   | effective (reason/importance)
            ===================+=========================+=========================+==================================
            Service1           |                 (w-D-M) |                 (w-A-R) | b-D, r-D, w-D  (user > group)
              Directory1       |                         | (b-A-R) (r-A-R)         | b-A, r-A, w-A
                Directory2     | (b-D-R) (r-D-R)         |                         | b-D, r-D, w-A  (revert group-dir1)
                  Directory3   |                 (w-A-R) |                 (w-D-M) | b-D, r-D, w-A  (user > group)
                    File1      |                         |                 (w-D-M) | b-D, r-D, w-D  (match > recursive)
              Directory4       |                         | (b-A-R) (r-A-R)         | b-A, r-A, w-A
                File2          | (b-D-M), (r-D-M)        |                 (w-D-R) | b-D, r-D, w-W
                  Directory5   |                         |                         | b-A, r-A, w-W
                    File3      |                         |                         | b-A, r-A, w-W
            Service2           |                         | (b-A-R)                 | b-A, r-D, w-D  (validate catalog)

        .. note::
            Permission :attr:`Permission.WRITE` can be created, but they don't actually have any use for the moment
            according to :class:`ServiceTHREDDS` implementation.

        .. seealso::
            Reference test server to explore supported formats by THREDDS service (many files and formats available):
            https://remotetest.unidata.ucar.edu/thredds/catalog/catalog.html

        .. versionchanged:: 3.5
            User and Group permissions for ``Directory1`` and ``Directory2`` have been swapped since new priorities make
            :term:`Direct Permissions` more important than :term:`Inherited Permissions <Inherited Permission>`.
            The :attr:`Access.DENY` was not being reverted with original definitions that assumed them to be of equal
            importance, and therefore plain ``DENY > ALLOW`` was working.
        """
        svc_type = ServiceTHREDDS.service_type
        svc1_name = "unittest-service-thredds-1"
        svc2_name = "unittest-service-thredds-2"
        dir_type = models.Directory.resource_type_name
        file_type = models.File.resource_type_name
        utils.TestSetup.delete_TestService(self, override_service_name=svc1_name)
        body = utils.TestSetup.create_TestService(self, override_service_name=svc1_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc1_id = info["resource_id"]
        utils.TestSetup.delete_TestService(self, override_service_name=svc2_name)
        body = utils.TestSetup.create_TestService(self, override_service_name=svc2_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc2_id = info["resource_id"]

        # create resources
        dir1_id, dir1_name = self.make_resource(dir_type, svc1_id, 1)
        dir2_id, dir2_name = self.make_resource(dir_type, dir1_id, 2)
        dir3_id, dir3_name = self.make_resource(dir_type, dir2_id, 3)
        dir4_id, dir4_name = self.make_resource(dir_type, svc1_id, 4)
        dir5_id, dir5_name = self.make_resource(dir_type, dir4_id, 5)
        # files must have '.nc' extension
        file1_id, file1_name = self.make_resource(file_type, dir3_id, "1.nc")
        file2_id, file2_name = self.make_resource(file_type, dir4_id, "2.nc")
        file3_id, file3_name = self.make_resource(file_type, dir5_id, "3.nc")  # pylint: disable=W0612

        # validate refused creation of invalid Directory or File under a leaf File resource
        path = "/services/{}/resources".format(svc1_name)
        for child_res_type in [dir_type, file_type]:
            data = {"resource_type": child_res_type, "parent_id": file1_id,
                    "resource_name": "unittest-service-thredds-forbidden-child-resource"}
            resp = utils.test_request(self, "POST", path=path, json=data, expect_errors=True,
                                      headers=self.json_headers, cookies=self.cookies)
            utils.check_response_basic_info(resp, 403, expected_method="POST")

        # assign permissions
        bAR = PermissionSet(Permission.BROWSE, Access.ALLOW, Scope.RECURSIVE)   # noqa
        bDR = PermissionSet(Permission.BROWSE, Access.DENY, Scope.RECURSIVE)    # noqa
        bDM = PermissionSet(Permission.BROWSE, Access.DENY, Scope.MATCH)        # noqa
        rAR = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)     # noqa
        rDR = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)      # noqa
        rDM = PermissionSet(Permission.READ, Access.DENY, Scope.MATCH)          # noqa
        wAR = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)    # noqa
        wDR = PermissionSet(Permission.WRITE, Access.DENY, Scope.RECURSIVE)     # noqa
        wDM = PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH)         # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc1_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc1_id, override_permission=wAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=dir1_id, override_permission=bAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=dir1_id, override_permission=rAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=dir2_id, override_permission=bDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=dir2_id, override_permission=rDR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=dir3_id, override_permission=wAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=dir3_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=file1_id, override_permission=wDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=dir4_id, override_permission=bAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=file2_id, override_permission=bDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=dir4_id, override_permission=rAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=file2_id, override_permission=rDM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=file2_id, override_permission=wDR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc2_id, override_permission=bAR)

        # login test user for which the permissions were set
        self.login_test_user()

        # directory path with various path formats, only actual directory listing should be allowed
        dir_prefixes = [svc1_name + "/catalog", svc1_name + "/fileServer", svc1_name + "/dodsC"]
        dir_suffixes = ["", "/catalog.html"]  # with or without explicit catalog HTML, this points to directory listing
        test_sub_dir = [
            (False, ""),
            (True, "/" + dir1_name),
            (False, "/{}/{}".format(dir1_name, dir2_name)),
            (False, "/{}/{}/{}".format(dir1_name, dir2_name, dir3_name)),
        ]
        for prefix, test_subdir, suffix in itertools.product(dir_prefixes, test_sub_dir, dir_suffixes):
            expect_allowed, subdir = test_subdir
            path = "/ows/proxy/{}{}{}".format(prefix, subdir, suffix)
            req = self.mock_request(path, method="GET")
            msg = "Using combination [GET, {}]".format(path)
            if expect_allowed:
                utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)
            else:
                utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)

        # top-level directory access with special catalog prefix and various formats considered
        # (all equivalently pointing directly to THREDDS catalog browsing)
        suffixes = ["", "/catalog", "/catalog.html", "/catalog.xml", "/catalog/catalog.html", "/catalog/catalog.xml"]
        for suffix in suffixes:
            path = "/ows/proxy/{}{}".format(svc2_name, suffix)
            req = self.mock_request(path, method="GET")
            msg = "Using combination [GET, {}]".format(path)
            utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)

        # file access with various formats, locations and accessors
        # using default config, they should all point toward the same resource regardless of formats after '.nc'
        test_files = [
            (False, "{}/{}/{}/{}".format(dir1_name, dir2_name, dir3_name, file1_name)),
            (False, "{}/{}".format(dir4_name, file2_name)),
            (True, "{}/{}/{}".format(dir4_name, dir5_name, file3_name)),
        ]
        for expect_allowed, file_path in test_files:
            file_prefixes = ["dap4", "dodsC", "fileServer"]  # format of files accessors (anything in *data_type*)
            file_suffixes = ["", ".dds", ".dmr.xml", ".html", ".ascii?"]  # different representations
            for prefix, suffix in itertools.product(file_prefixes, file_suffixes):
                path = "/ows/proxy/{}/{}/{}{}".format(svc1_name, prefix, file_path, suffix)
                req = self.mock_request(path, method="GET")
                msg = "Using combination [GET, {}]".format(path)
                if expect_allowed:
                    utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)
                else:
                    utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)

        # validate that unknown prefix is always denied even if resource is otherwise allowed when prefix is known
        # this is mostly to ensure that new prefix/formats added to THREDDS don't suddenly provide access unexpectedly
        test_allowed_resources = [
            "/" + dir1_name,
            "{}/{}/{}".format(dir4_name, dir5_name, file3_name),
        ]
        unknown_prefix = "random"
        for allowed_resource in test_allowed_resources:
            path = "/ows/proxy/{}/{}/{}".format(svc1_name, unknown_prefix, allowed_resource)
            req = self.mock_request(path, method="GET")
            msg = "Unknown prefix must be refused even when resource is normally allowed. Using [GET, {}]".format(path)
            utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)

    @utils.mocked_get_settings
    def test_ServiceTHREDDS_custom_config(self):
        """
        Evaluate that :class:`ServiceTHREDDS` behaviour results into wanted behaviour of corresponding custom settings.

        .. note::
            Since we employ mocked requests to call :meth:`MagpieOWSSecurity.check_request` directly
            (instead of going through the normal application receiving incoming requests), we need to pass down the
            custom settings manually as the application would provide them for us.
        """
        svc_name = "unittest-service-thredds-custom"
        svc_type = ServiceTHREDDS.service_type
        utils.TestSetup.delete_TestService(self, override_service_name=svc_name)

        with NamedTemporaryFile(mode="w", suffix=".yml") as config:
            # generate a custom config for test THREDDS service
            config.write(inspect.cleandoc("""
                providers:
                    {name}:
                        # mandatory provider settings
                        url: http://localhost
                        type: {type}
                        # custom configuration definition
                        configuration:
                            file_patterns:
                                # note: 
                                #   following patterns should have only one-double backslash escape each,
                                #   but needs quadruple in this case because of 2-steps (dump to YAML, read from YAML)
                                - ".*\\\\.ncml"   # matched before plain '.nc', will correspond to another resource
                                - ".*\\\\.nc"
                            data_type:
                                prefixes:
                                    # only allow these variants, other should be blocked ("dap4", "wcs", "wms")
                                    - dodsC
                                    - fileServer
                            metadata_type:
                                prefixes:
                                    # only allow these variants, others should be blocked ("ncml", "uddc", "iso")
                                    - null
                                    - catalog
                permissions:  # fill only because required
            """.format(name=svc_name, type=svc_type)))
            config.flush()  # force write to file
            settings = {"magpie.config_path": config.name}
            # trigger application startup to load providers configuration
            utils.get_test_magpie_app(settings)

        # obtain service to view applied config
        path = "/services/{}".format(svc_name)
        resp = utils.test_request(self, "GET", path, headers=self.json_headers, cookies=self.cookies)
        body = utils.check_response_basic_info(resp, 200, expected_method="GET")
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc_id = info["resource_id"]

        # validate that created service on startup has custom settings from providers config file
        utils.check_val_is_in("configuration", info)
        svc_config = info["configuration"]  # type: JSON
        utils.check_val_not_equal(svc_config, None)
        utils.check_val_is_in("file_patterns", svc_config)
        utils.check_val_is_in("data_type", svc_config)
        utils.check_val_is_in("metadata_type", svc_config)
        utils.check_val_equal(svc_config["file_patterns"], [".*\\.ncml", ".*\\.nc"])
        utils.check_val_equal(svc_config["data_type"]["prefixes"], ["dodsC", "fileServer"])
        utils.check_val_equal(svc_config["metadata_type"]["prefixes"], [None, "catalog"])

        # create resources
        dir_id, dir_name = self.make_resource(models.Directory.resource_type_name, svc_id)
        file_id, file_name = self.make_resource(models.File.resource_type_name, dir_id, ".nc")
        _, file_ncml_name = self.make_resource(models.File.resource_type_name, dir_id, ".ncml")
        _, file_html_name = self.make_resource(models.File.resource_type_name, dir_id, ".nc.html")

        # create permissions, using specific match to only evaluate explicitly the resolution modified by custom config
        bAM = PermissionSet(Permission.BROWSE, Access.ALLOW, Scope.MATCH)       # noqa
        rAM = PermissionSet(Permission.READ, Access.ALLOW, Scope.MATCH)         # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=dir_id, override_permission=bAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=file_id, override_permission=rAM)

        # login test user for which the permissions were set
        self.login_test_user()

        # directory can be accessed only via catalog according to permissions
        path = "/ows/proxy/{}/catalog/{}".format(svc_name, dir_name)
        req = self.mock_request(path, method="GET", settings=settings)
        msg = "Directory catalog access should be allowed. Using [GET, {}]".format(path)
        utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)
        # using the same catalog prefix with any file is invalid (catalog is BROWSE metadata, files require READ data)
        for test_file in [file_name, file_html_name, file_ncml_name]:
            path = "/ows/proxy/{}/catalog/{}/{}".format(svc_name, dir_name, test_file)
            req = self.mock_request(path, method="GET", settings=settings)
            msg = "File catalog access should be denied. Using [GET, {}]".format(path)
            utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)

        # file NC/HTML should be parsed as the same Resource which is allowed access when using allowed prefixes
        # (same resource because matching '.*.nc' regex, NCML file matched by other '.*.ncml' regex, so other Resource)
        # only accessible via specified data prefixes
        allowed_files = [file_name, file_html_name]
        known_prefixes = ["dodsC", "fileServer"]
        for prefix in known_prefixes:
            for test_file in allowed_files:
                path = "/ows/proxy/{}/{}/{}/{}".format(svc_name, prefix, dir_name, test_file)
                req = self.mock_request(path, method="GET", settings=settings)
                msg = "File access should be allowed. Using [GET, {}]".format(path)
                utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)
            # file NCML must be parsed as completely different resource, and therefore be denied even with valid prefix
            path = "/ows/proxy/{}/{}/{}/{}".format(svc_name, prefix, dir_name, file_ncml_name)
            req = self.mock_request(path, method="GET", settings=settings)
            msg = "File pattern should make parsing of NCML resource separate than NC file, and should be denied. "
            msg += "Using [GET, {}]".format(path)
            utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)

        # using unknown prefixes, otherwise allowed file should always be denied
        unknown_prefixes = ["ncml", "dap4"]  # purposely take normally allowed THREDDS prefixes, validate active config
        allowed_resources = [dir_name, "{}/{}".format(dir_name, file_name), "{}/{}".format(dir_name, file_html_name)]
        for prefix in unknown_prefixes:
            for target in allowed_resources:
                path = "/ows/proxy/{}/{}/{}".format(svc_name, prefix, target)
                req = self.mock_request(path, method="GET", settings=settings)
                msg = "Allowed resources should be resolved as denied when using an unregistered configuration prefix."
                msg += "Using [GET, {}]".format(path)
                utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)

    @unittest.skip("impl")
    @pytest.mark.skip
    @utils.mocked_get_settings
    def test_ServiceNCWMS2_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceNCWMS2` against a mocked `Magpie` adapter for `Twitcher`.
        """
        raise NotImplementedError  # FIXME

    @utils.mocked_get_settings
    def test_ServiceGeoserverWMS_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceGeoserverWMS` against a mocked `Magpie` adapter for `Twitcher`.

        Legend::

            c: GetCapabilities  (only permission parsed differently)
            m: GetMap           (other permissions applicable, but they are all parsed the same as GetMap)
            A: allow
            D: deny
            M: match
            R: recursive

        Permissions Applied::
                                        user            group           effective
            Service1                                    (c-A-R)         c-A, m-D
                Workspace1              (c-D-M)                         c-D, m-D
                Workspace2              (m-A-M)                         c-A, m-A
                    [Layer]                                             c-A, m-D
            Service2                                    (m-A-R)         c-D, m-A
                Workspace3                              (c-A-M)         c-A, m-A
                    [Layer]                                             c-A, m-A
        """
        svc1_name = "unittest-service-geoserverwms1"
        svc2_name = "unittest-service-geoserverwms2"
        svc_type = ServiceGeoserverWMS.service_type
        res_type = models.Workspace.resource_type_name
        for svc_name in [svc1_name, svc2_name]:
            utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
        body = utils.TestSetup.create_TestService(self, override_service_name=svc1_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc1_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=svc2_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        svc2_id = info["resource_id"]

        # create workspaces
        res1_id, res1_name = self.make_resource(res_type, svc1_id, 1, "UNITTEST_WORKSPACE")
        res2_id, res2_name = self.make_resource(res_type, svc1_id, 2, "UNITTEST_WORKSPACE")
        res3_id, res3_name = self.make_resource(res_type, svc2_id, 3, "UNITTEST_WORKSPACE")

        # assign permissions
        cAR = PermissionSet(Permission.GET_CAPABILITIES, Access.ALLOW, Scope.RECURSIVE)     # noqa
        cAM = PermissionSet(Permission.GET_CAPABILITIES, Access.ALLOW, Scope.MATCH)         # noqa
        cDM = PermissionSet(Permission.GET_CAPABILITIES, Access.DENY, Scope.MATCH)          # noqa
        mAM = PermissionSet(Permission.GET_MAP, Access.ALLOW, Scope.MATCH)                  # noqa
        mAR = PermissionSet(Permission.GET_MAP, Access.ALLOW, Scope.RECURSIVE)              # noqa
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc1_id, override_permission=cAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res1_id, override_permission=cDM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=res2_id, override_permission=mAM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc2_id, override_permission=mAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=res3_id, override_permission=cAM)

        self.login_test_user()

        # parsing must be the same whether the service has GeoServer prefix or not
        for prefix in ["", "/geoserver"]:

            # GetCapabilities of all Workspaces
            path = "/ows/proxy/{}{}/wms?request=getcapabilities".format(svc1_name, prefix)
            req = self.mock_request(path, method="GET")
            utils.check_no_raise(lambda: self.ows.check_request(req))
            path = "/ows/proxy/{}{}/wms?request=getcapabilities".format(svc2_name, prefix)
            req = self.mock_request(path, method="GET")
            utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

            # GetCapabilities of specific Workspace
            # GetCapabilities is always applicable on Service only
            #   allow/deny applied on children resources should not impact result according to permission on service
            path = "/ows/proxy/{}{}/{}/wms?request=getcapabilities".format(svc1_name, prefix, res1_name)
            req = self.mock_request(path, method="GET")
            utils.check_no_raise(lambda: self.ows.check_request(req))
            path = "/ows/proxy/{}{}/{}/wms?request=getcapabilities".format(svc1_name, prefix, res2_name)
            req = self.mock_request(path, method="GET")
            utils.check_no_raise(lambda: self.ows.check_request(req))
            path = "/ows/proxy/{}{}/{}/wms?request=getcapabilities".format(svc2_name, prefix, res3_name)
            req = self.mock_request(path, method="GET")
            utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

            # GetMap of layer in Workspace (Workspace inferred from path prefix or layer name)
            # workspace 1
            svc_prefix = "/ows/proxy/{}{}".format(svc1_name, prefix)
            layer_name = "{}:TEST_LAYER".format(res1_name)
            for workspace_prefix in ["", "/" + res1_name]:
                path = "{}{}/wms?request=getmap&layers={}".format(svc_prefix, workspace_prefix, layer_name)
                req = self.mock_request(path, method="GET")
                msg = "Using combination [{}, {}]".format("GET", path)
                utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)
            # workspace 2
            layer_name = "{}:TEST_LAYER".format(res2_name)
            for workspace_prefix in ["", "/" + res2_name]:
                path = "{}{}/wms?request=getmap&layers={}".format(svc_prefix, workspace_prefix, layer_name)
                req = self.mock_request(path, method="GET")
                msg = "Using combination [{}, {}]".format("GET", path)
                utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=msg)
            # workspace 3
            svc_prefix = "/ows/proxy/{}{}".format(svc2_name, prefix)
            layer_name = "{}:TEST_LAYER".format(res3_name)
            for workspace_prefix in ["", "/" + res3_name]:
                path = "{}{}/wms?request=getmap&layers={}".format(svc_prefix, workspace_prefix, layer_name)
                req = self.mock_request(path, method="GET")
                msg = "Using combination [{}, {}]".format("GET", path)
                utils.check_no_raise(lambda: self.ows.check_request(req), msg=msg)

    @unittest.skip("impl")
    @pytest.mark.skip
    @utils.mocked_get_settings
    def test_ServiceWFS_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceWFS` against a mocked `Magpie` adapter for `Twitcher`.
        """
        raise NotImplementedError  # FIXME

    @utils.mocked_get_settings
    def test_ServiceWPS_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceWFS` against a mocked `Magpie` adapter for `Twitcher`.

        Legend::

            c: GetCapabilities (*)
            d: DescribeProcess
            e: Execute
            A: allow
            D: deny
            M: match
            R: recursive

        Permissions Applied::
                                        user        group               effective
            Service1                    (g-A-R)                         c-A,    d-D, e-D
                Process1                (e-A-M)     (d-A-M)             c-A,    d-A, e-A
            Service2                    (d-A-R)     (c-A-R)             c-A,    d-A, e-D
                Process2                            (c-D-M), (e-A-M)    c-A(*), d-A, e-A
                Process3                (e-D-M)                         c-A,    d-A, e-D

        .. note:: (*)
            All ``GetCapabilities`` requests completely ignore ``identifier`` query parameter by resolving immediately
            to the parent WPS Service since no Process applies in this case.

            For this reason, although ``(c-D-M)`` is applied on ``Process2``, Process ``identifier`` does not take place
            in ``GetCapabilities``. Therefore, the ACL is immediately resolved with the parent ``Service2`` permission
            of ``(c-A-R)`` which grants effective access.
        """
        # create services
        wps1_name = "unittest-service-wps-1"
        wps2_name = "unittest-service-wps-2"
        svc_type = ServiceWPS.service_type
        proc_type = models.Process.resource_type_name
        for svc_name in [wps1_name, wps2_name]:
            utils.TestSetup.delete_TestService(self, override_service_name=svc_name)
        body = utils.TestSetup.create_TestService(self, override_service_name=wps1_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        wps1_id = info["resource_id"]
        body = utils.TestSetup.create_TestService(self, override_service_name=wps2_name, override_service_type=svc_type)
        info = utils.TestSetup.get_ResourceInfo(self, override_body=body)
        wps2_id = info["resource_id"]

        # create processes
        proc1_id, proc1_name = self.make_resource(proc_type, wps1_id, 1)
        proc2_id, proc2_name = self.make_resource(proc_type, wps2_id, 2)
        proc3_id, proc3_name = self.make_resource(proc_type, wps2_id, 3)

        # assign permissions
        cAR = PermissionSet(Permission.GET_CAPABILITIES, Access.ALLOW, Scope.RECURSIVE)     # noqa
        dAM = PermissionSet(Permission.DESCRIBE_PROCESS, Access.ALLOW, Scope.MATCH)         # noqa
        dAR = PermissionSet(Permission.DESCRIBE_PROCESS, Access.ALLOW, Scope.RECURSIVE)     # noqa
        eAM = PermissionSet(Permission.EXECUTE, Access.ALLOW, Scope.MATCH)                  # noqa
        eDM = PermissionSet(Permission.EXECUTE, Access.DENY, Scope.MATCH)                   # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=wps1_id, override_permission=cAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=proc1_id, override_permission=eAM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=proc1_id, override_permission=dAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=wps2_id, override_permission=dAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=wps2_id, override_permission=cAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=proc2_id, override_permission=eAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=proc3_id, override_permission=eDM)

        # login test user for which the permissions were set
        self.login_test_user()

        # note:
        #   Following requests use various 'service' and 'request' values that do not necessarily match the exact format
        #   of corresponding enums to validate the request query parameters are parsed correctly with combinations that
        #   are actually handled by the real WPS service.

        # Service1 GET requests
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

        # Process1 GET requests
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

        # Service2 GET requests
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

        # Process2 GET requests
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

        # Process3 GET requests
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

        # evaluate parsing of POST-formatted Execute requests
        # (source: https://docs.geoserver.org/stable/en/user/services/wps/operations.html)
        wps_xml_post_body_template = inspect.cleandoc("""
        <?xml version="1.0" encoding="UTF-8"?>
        <wps:Execute version="1.0.0" service="WPS"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.opengis.net/wps/1.0.0" 
         xmlns:wfs="http://www.opengis.net/wfs" xmlns:wps="http://www.opengis.net/wps/1.0.0" 
         xmlns:ows="http://www.opengis.net/ows/1.1" xmlns:gml="http://www.opengis.net/gml"
         xmlns:ogc="http://www.opengis.net/ogc" xmlns:wcs="http://www.opengis.net/wcs/1.1.1"
         xmlns:xlink="http://www.w3.org/1999/xlink" xsi:schemaLocation="http://www.opengis.net/wps/1.0.0
         http://schemas.opengis.net/wps/1.0.0/wpsAll.xsd"
        >
          <ows:Identifier>{process}</ows:Identifier>
          <wps:DataInputs>
            <wps:Input>
              <ows:Identifier>geom</ows:Identifier>
              <wps:Data>
                <wps:ComplexData mimeType="application/wkt"><![CDATA[POINT(0 0)]]></wps:ComplexData>
              </wps:Data>
            </wps:Input>
          </wps:DataInputs>
          <wps:ResponseForm>
            <wps:RawDataOutput mimeType="application/gml-3.1.1">
              <ows:Identifier>result</ows:Identifier>
            </wps:RawDataOutput>
          </wps:ResponseForm>
        </wps:Execute>
        """)
        xml_headers = {"Content-Type": CONTENT_TYPE_TXT_XML}

        # Process2 POST Execute
        path = "/ows/proxy/{}".format(wps2_name)
        body = wps_xml_post_body_template.format(process=proc2_name).encode()
        req = self.mock_request(path, method="POST", body=body, params=None, headers=xml_headers)
        utils.check_no_raise(lambda: self.ows.check_request(req))

        # Process3 POST Execute
        path = "/ows/proxy/{}".format(wps2_name)
        body = wps_xml_post_body_template.format(process=proc3_name).encode()
        req = self.mock_request(path, method="POST", body=body, params=None, headers=xml_headers)
        utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden)

    @utils.mocked_get_settings
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
        self.login_test_user()

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
    @utils.mocked_get_settings
    def test_ServiceADES_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceADES` against a mocked `Magpie` adapter for `Twitcher`.

        .. note::
            Service of type :class:`ServiceADES` is a combination of :class:`ServiceAPI` and :class:`ServiceWPS` with
            corresponding resources accessed through different endpoints and formats.
        """
        raise NotImplementedError  # FIXME: see https://github.com/Ouranosinc/Magpie/issues/360

    @utils.mocked_get_settings
    def test_ServiceGeoserver_effective_permissions(self):
        """
        Evaluates functionality of :class:`ServiceGeoserver` against a mocked `Magpie` adapter for `Twitcher`.

        The :class:`ServiceGeoserver` implementation works as a combination of many :term:`OWS` sub-services.
        Validate that different resource types and distinct permissions can be simultaneously applied on them.
        Effective permissions must be resolved with the appropriate :term:`OWS` service accordingly with request
        parameters.

        Legend::

            []: Resource does not exist in Magpie, but position matches actual resource for the target service
            gc: GetCapabilities (shared by all OWS)
            gf: GetFeature permission (WFS Layer)
            gi: GetFeatureInfo permission (WMS Layer)
            gm: GetMap (WMS Layer)
            dp: DescribeProcess permission (WPS Process)
            r: Read permission (API Route)
            w: Write permission (API Route)
            A: allow
            D: deny
            M: match        (makes sense only on layer for any permission except GetCapabilities on service itself)
            R: recursive    (resolution for multiple layers, permissions have no use on Service or Workspace themselves)

        Permissions Applied::
                                        user        group       effective (detail)
            Service1                    (gc-A-R)    (gm-D-R)    gc-A, gf-D, gi-D, gm-D
                Workspace1              (dp-A-R)    (gf-A-R)    dp-A, gf-A, gi-D, gm-D (no match on Workspace itself)
                    Layer11                         (gi-A-R)    dp-D, gf-A, gi-A, gm-D
                    Layer12             (gf-D-M)    (gm-A-M)    dp-D, gf-D, gi-A, gm-A (match > recursive)
                    Layer13             (gm-A-R)                dp-D, gf-A, gi-A, gm-A (effective user > group)
                    [Layer4]                                    dp-D, gf-A, gi-D (doesn't exist, only R apply)
                    Process11                                   dp-A, gf-D, gi-D (gf/gi don't apply on Process)
                    Process12           (dp-D-M)                dp-D, gf-D, gi-D
                    Process13                       (dp-D-M)    dp-A, gf-D, gi-D (effective workspace user > group)
                    [Process4]                                  dp-A, gf-D, gi-D
                Workspace2                          (gf-A-R)    dp-D, gf-A, gi-D
                    Layer21             (gf-D-M)                dp-D, gf-D, gi-D (revoke access, user > group)
                    Layer22                         (gf-D-M)    dp-D, gf-D, gi-D (revoke access, both groups)
                    Layer23             (gf-A-M)    (gf-D-M)    dp-D, gf-A, gi-D (allowed access, user > group)
                Route1                                          r-D, w-D (denied default)
                    Route2              (r-A-R)                 r-A, w-D
                Route3                  (r-A-R)     (w-A-R)     r-A, w-A
                    Route4                          (w-D-M)     r-A, w-D (revoked access)

        .. note::
            Permissions that do not applied to a given sub-:term:`OWS` implementation are automatically denied.
            For example, 'GetFeatureInfo' cannot be applied for a 'Process' nor can 'DescribeProcess' for a 'Layer'.
        """
        svc_type = ServiceGeoserver.service_type
        svc1_name = "unittest-service-geoserver-1"
        w1_name = "workspace1"
        w2_name = "workspace2"
        wx_name = "fake-workspace"
        l11_name = "layer11"
        l12_name = "layer12"
        l13_name = "layer13"
        l14_name = "layer14"
        l21_name = "layer21"
        l22_name = "layer22"
        l23_name = "layer23"
        p11_name = "process11"
        p12_name = "process12"
        p13_name = "process13"
        p14_name = "process14"
        r1_name = "route1"
        r2_name = "route2"
        r3_name = "route3"
        r4_name = "route4"

        utils.TestSetup.delete_TestService(self, svc1_name)
        svc1_id, w1_id = utils.TestSetup.create_TestServiceResourceTree(
            self,
            override_service_name=svc1_name, override_service_type=svc_type,
            override_resource_names=[w1_name], override_resource_types=[models.Workspace.resource_type_name],
        )
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=w1_id,
            override_resource_name=l11_name,
            override_resource_type=models.Layer.resource_type_name
        )
        l11_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=w1_id,
            override_resource_name=l12_name,
            override_resource_type=models.Layer.resource_type_name
        )
        l12_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=w1_id,
            override_resource_name=l13_name,
            override_resource_type=models.Layer.resource_type_name
        )
        l13_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=w1_id,
            override_resource_name=p12_name,
            override_resource_type=models.Process.resource_type_name
        )
        p12_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=w1_id,
            override_resource_name=p13_name,
            override_resource_type=models.Process.resource_type_name
        )
        p13_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=svc1_id,
            override_resource_name=w2_name,
            override_resource_type=models.Workspace.resource_type_name
        )
        w2_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=w2_id,
            override_resource_name=l21_name,
            override_resource_type=models.Layer.resource_type_name
        )
        l21_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=w2_id,
            override_resource_name=l22_name,
            override_resource_type=models.Layer.resource_type_name
        )
        l22_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=w2_id,
            override_resource_name=l23_name,
            override_resource_type=models.Layer.resource_type_name
        )
        l23_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=svc1_id,
            override_resource_name=r1_name,
            override_resource_type=models.Route.resource_type_name
        )
        r1_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=r1_id,
            override_resource_name=r2_name,
            override_resource_type=models.Route.resource_type_name
        )
        r2_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=svc1_id,
            override_resource_name=r3_name,
            override_resource_type=models.Route.resource_type_name
        )
        r3_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]
        info = utils.TestSetup.create_TestResource(
            self,
            parent_resource_id=r3_id,
            override_resource_name=r4_name,
            override_resource_type=models.Route.resource_type_name
        )
        r4_id = utils.TestSetup.get_ResourceInfo(self, info)["resource_id"]

        # create permissions
        gcAR = PermissionSet(Permission.GET_CAPABILITIES, Access.ALLOW, Scope.RECURSIVE)    # noqa
        gfAR = PermissionSet(Permission.GET_FEATURE, Access.ALLOW, Scope.RECURSIVE)         # noqa
        gfAM = PermissionSet(Permission.GET_FEATURE, Access.ALLOW, Scope.MATCH)             # noqa
        gfDM = PermissionSet(Permission.GET_FEATURE, Access.DENY, Scope.MATCH)              # noqa
        giAR = PermissionSet(Permission.GET_FEATURE_INFO, Access.ALLOW, Scope.RECURSIVE)    # noqa
        gmAM = PermissionSet(Permission.GET_MAP, Access.ALLOW, Scope.MATCH)                 # noqa
        gmAR = PermissionSet(Permission.GET_MAP, Access.ALLOW, Scope.RECURSIVE)             # noqa
        gmDR = PermissionSet(Permission.GET_MAP, Access.DENY, Scope.RECURSIVE)              # noqa
        dpAR = PermissionSet(Permission.DESCRIBE_PROCESS, Access.ALLOW, Scope.RECURSIVE)    # noqa
        dpDM = PermissionSet(Permission.DESCRIBE_PROCESS, Access.DENY, Scope.MATCH)         # noqa
        rAR = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE)                 # noqa
        wAR = PermissionSet(Permission.WRITE, Access.ALLOW, Scope.RECURSIVE)                # noqa
        wDM = PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH)                     # noqa
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=svc1_id, override_permission=gcAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=svc1_id, override_permission=gmDR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=w1_id, override_permission=gfAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=w1_id, override_permission=dpAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=l11_id, override_permission=giAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=l12_id, override_permission=gfDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=l12_id, override_permission=gmAM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=l13_id, override_permission=gmAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=p12_id, override_permission=dpDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=p13_id, override_permission=dpDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=w2_id, override_permission=gfAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=l21_id, override_permission=gfDM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=l22_id, override_permission=gfDM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=l23_id, override_permission=gfAM)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=l23_id, override_permission=gfDM)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=r2_id, override_permission=rAR)
        utils.TestSetup.create_TestUserResourcePermission(self, override_resource_id=r3_id, override_permission=rAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=r3_id, override_permission=wAR)
        utils.TestSetup.create_TestGroupResourcePermission(self, override_resource_id=r4_id, override_permission=wDM)

        # login test user for which the permissions were set
        self.login_test_user()

        # service calls
        svc_path = "/ows/proxy/{}".format(svc1_name)

        def _msg(_path, _params):
            # type: (Str, Dict[Str, Str]) -> Str
            _qs = "&".join("{}={}".format(k, v) for k, v in _params.items())
            path_qs = "{}?{}".format(_path, _qs) if _qs else _path
            return "Using combination [{}, {}]".format("GET", path_qs)

        def _scope(workspace, layer):
            # type: (Str, Str) -> Str
            return "{}:{}".format(workspace, layer)

        def _test(_path, _params, allow, method="GET"):
            # type: (Str, Dict[Str, Str], bool, Str) -> None
            req = self.mock_request(_path, method=method, params=_params)
            if allow:
                utils.check_no_raise(lambda: self.ows.check_request(req), msg=_msg(_path, _params))
            else:
                utils.check_raises(lambda: self.ows.check_request(req), OWSAccessForbidden, msg=_msg(_path, _params))

        # request for any OWS
        #   <HOST>/geoserver[/<WORKSPACE>]/<OWS>?request=GetCapabilities
        for path in [svc_path, "{}/{}".format(svc_path, w1_name)]:
            for ows in ["WFS", "WMS", "WPS"]:
                ows_path = "{}/{}".format(path, ows.lower())
                _test(ows_path, {"request": Permission.GET_CAPABILITIES.title}, allow=True)

        # permission is valid on resource for both WFS and WMS, but they expect different parameter names
        #   <HOST>/geoserver[/<WORKSPACE>]/[wfs|wms]?request=GetFeatureInfo&version=<>&[typeNames|layers]=<LAYER>
        w1_wfs_path = "{}/{}/wfs".format(svc_path, w1_name)
        w1_wms_path = "{}/{}/wms".format(svc_path, w1_name)
        w1_wps_path = "{}/{}/wps".format(svc_path, w1_name)
        w2_wfs_path = "{}/{}/wfs".format(svc_path, w2_name)
        wx_wfs_path = "{}/{}/wfs".format(svc_path, wx_name)
        wx_wms_path = "{}/{}/wms".format(svc_path, wx_name)
        svc_wfs_path = "{}/wfs".format(svc_path)
        svc_wms_path = "{}/wms".format(svc_path)
        svc_wps_path = "{}/wps".format(svc_path)
        wx_l1 = _scope(wx_name, l11_name)
        w1_l1 = _scope(w1_name, l11_name)
        w1_l2 = _scope(w1_name, l12_name)
        w1_l3 = _scope(w1_name, l13_name)
        w1_l4 = _scope(w1_name, l14_name)
        w1_p1 = _scope(w1_name, p11_name)
        w1_p2 = _scope(w1_name, p12_name)
        w1_p3 = _scope(w1_name, p13_name)
        w1_p4 = _scope(w1_name, p14_name)
        w2_l1 = _scope(w2_name, l21_name)
        w2_l2 = _scope(w2_name, l22_name)
        w2_l3 = _scope(w2_name, l23_name)

        # API endpoints only valid with exact paths
        r1_path = "{}/{}".format(svc_path, r1_name)
        r2_path = "{}/{}".format(svc_path, r2_name)
        r3_path = "{}/{}".format(svc_path, r3_name)
        r4_path = "{}/{}".format(svc_path, r4_name)
        _test(r1_path, {}, method="GET", allow=False)
        _test(r2_path, {}, method="GET", allow=True)
        _test(r3_path, {}, method="GET", allow=True)
        _test(r4_path, {}, method="GET", allow=True)
        _test(r1_path, {}, method="POST", allow=False)
        _test(r2_path, {}, method="POST", allow=False)
        _test(r3_path, {}, method="POST", allow=True)
        _test(r4_path, {}, method="POST", allow=False)
        _test("/random", {}, method="GET", allow=False)
        _test("/random", {}, method="POST", allow=False)

        # Layer1, mismatching permission for WMS
        _test(svc_wms_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l1}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l1}, allow=False)

        # Layer1, valid requests (WFS)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l1}, allow=True)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l1}, allow=True)

        # Layer1, mismatched OWS path/param
        #   - When <WORKSPACE> is not directly in the path, because query parameters to extract <WORKSPACE>:<LAYER>
        #     mismatch the expected OWS service from the path (not 'layers' for WFS, not 'typeNames' for WMS),
        #     the closest resolved requested resource is the service itself.
        #     That service does not have the requested permissions (directly on it), so access is forbidden.
        #   - When <WORKSPACE> is directly in the path for WFS, the requested resource can be resolved more precisely
        #     as the Workspace instead of the top-level service.
        #   - For allowed WFS test cases with <WORKSPACE> in path, because 'GetFeature' is applied recursively on
        #     Workspace, access is granted even if the request parameter is erroneous to retrieve its appropriate Layer
        #     resource. Since wrong parameter is used, Magpie does validate the path parameter against the scoped
        #     Workspace name. The actual OWS should still normally respond with bad request since the wrong request
        #     parameter (bad 'layers' instead of WFS 'typeNames') is provided for that OWS. The request remains invalid
        #     even if
        #     accessible, but Magpie/Twitcher job is over at that point.
        #   - When OWS is WMS, GetFeature does not apply. Therefore, access refused.
        _test(svc_wms_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l1}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l1}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l1}, allow=True)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_name}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, "layers": w1_name}, allow=True)

        # Layer1, valid requests (WMS)
        _test(svc_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l1}, allow=True)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l1}, allow=True)

        # Layer1, mismatching permission for WFS
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l1}, allow=False)

        # Layer1, missing workspace
        _test(svc_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_name}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_name}, allow=False)

        # Layer1, mismatched OWS path/param
        #   in this case, GetFeatureInfo permission is applied directly on Layer
        #   invalid params makes retrieval of the Layer resource to fail, and therefore access is blocked
        _test(svc_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l1}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l1}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l1}, allow=False)

        # Layer2, valid requests and mismatched OWS/path
        #   - Resource is always blocked because of explicit deny permission on it when it is matched.
        #   - When OWS service and request parameters mismatch, the parent workspace is resolved.
        #     In that case, access can be granted because recursive Workspace permission is allowed.
        _test(svc_wms_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l2}, allow=False)
        _test(svc_wms_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l2}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l2}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l2}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l2}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l2}, allow=False)
        # mismatch OWS params resolve using workspace permission
        # WMS fails because of invalid permission, WFS 'succeeds' access because of valid permission.
        # WFS should fail on the instance side because of missing 'typeNames' parameter though.
        _test(w1_wms_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l2}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l2}, allow=True)

        # Layer2, valid requests and mismatched OWS/path
        #   - Resource blocked when matched because no permission directly on the layer.
        #   - When mismatched OWS/path, fail to get target layer, but still blocked because
        #     Workspace also doesn't have that permission.
        _test(svc_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l2}, allow=False)
        _test(svc_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l2}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l2}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l2}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l2}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l2}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l2}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l2}, allow=False)

        # invalid permission not applicable to WFS/WMS
        _test(svc_wms_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": w1_l1}, allow=False)
        _test(svc_wfs_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": w1_l1}, allow=False)
        _test(w1_wms_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": w1_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": w1_l1}, allow=False)

        # mismatch workspace between path and scoped layer
        # result is no workspace being matched, therefore permissions on them are not applied
        _test(w1_wms_path, {"request": Permission.GET_FEATURE.title, "layers": wx_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": wx_l1}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": wx_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": wx_l1}, allow=False)
        _test(wx_wms_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l1}, allow=False)
        _test(wx_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l1}, allow=False)
        _test(wx_wms_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l1}, allow=False)
        _test(wx_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l1}, allow=False)

        # invalid permission not applicable to WPS
        _test(svc_wps_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l1}, allow=False)
        _test(svc_wps_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l1}, allow=False)
        _test(svc_wps_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l1}, allow=False)
        _test(svc_wps_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l1}, allow=False)
        _test(w1_wps_path, {"request": Permission.GET_FEATURE.title, "layers": w1_l1}, allow=False)
        _test(w1_wps_path, {"request": Permission.GET_FEATURE.title, "typeNames": w1_l1}, allow=False)
        _test(w1_wps_path, {"request": Permission.GET_FEATURE_INFO.title, "layers": w1_l1}, allow=False)
        _test(w1_wps_path, {"request": Permission.GET_FEATURE_INFO.title, "typeNames": w1_l1}, allow=False)

        # valid WPS requests
        #   - Workspace only expected to work when in path because 'identifier' is not linked to workspace
        #   - Process2 is explicitly denied, so access still blocked even when resource is properly resolved.
        _test(w1_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": p11_name}, allow=True)
        _test(w1_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": p12_name}, allow=False)
        _test(w1_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": p13_name}, allow=True)
        _test(w1_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": p14_name}, allow=True)
        # other cases all invalid since workspace cannot be resolved
        _test(svc_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": p11_name}, allow=False)
        _test(svc_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": p12_name}, allow=False)
        _test(svc_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": p13_name}, allow=False)
        _test(svc_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": w1_p1}, allow=False)
        _test(svc_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": w1_p2}, allow=False)
        _test(svc_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": w1_p3}, allow=False)
        _test(svc_wps_path, {"request": Permission.DESCRIBE_PROCESS.title, "identifier": w1_p4}, allow=False)

        # valid WMS requests
        # validate that effective resolution considering user/group priority and recursive/match scope priority work
        _test(svc_wms_path, {"request": Permission.GET_MAP.title, "layers": w1_l1}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_MAP.title, "layers": w1_l1}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_MAP.title, "layers": l11_name}, allow=False)
        _test(svc_wms_path, {"request": Permission.GET_MAP.title, "layers": w1_l2}, allow=True)
        _test(w1_wms_path, {"request": Permission.GET_MAP.title, "layers": w1_l2}, allow=True)
        _test(w1_wms_path, {"request": Permission.GET_MAP.title, "layers": l12_name}, allow=True)
        _test(svc_wms_path, {"request": Permission.GET_MAP.title, "layers": w1_l3}, allow=True)
        _test(w1_wms_path, {"request": Permission.GET_MAP.title, "layers": w1_l3}, allow=True)
        _test(w1_wms_path, {"request": Permission.GET_MAP.title, "layers": l13_name}, allow=True)
        _test(svc_wms_path, {"request": Permission.GET_MAP.title, "layers": w1_l4}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_MAP.title, "layers": w1_l4}, allow=False)
        _test(w1_wms_path, {"request": Permission.GET_MAP.title, "layers": l14_name}, allow=False)

        # using either the 'typename' or 'typenames' parameter lets WFS retrieve layers indistinguishably
        alt_name = "typeName"
        def_name = "typeNames"

        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, alt_name: w1_l1}, allow=True)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, alt_name: w1_l2}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, alt_name: w1_name}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, alt_name: w1_l2}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, alt_name: w1_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, alt_name: wx_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, alt_name: w1_l2}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, alt_name: w1_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, alt_name: wx_l1}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, alt_name: w1_l2}, allow=False)

        def _add_both(value):
            return {alt_name: value, def_name: value}

        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, **_add_both(w1_l1)}, allow=True)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, **_add_both(w1_l2)}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, **_add_both(w1_name)}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, **_add_both(w1_l2)}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, **_add_both(w1_l1)}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, **_add_both(wx_l1)}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, **_add_both(w1_l2)}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, **_add_both(w1_l1)}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, **_add_both(wx_l1)}, allow=False)
        _test(w1_wfs_path, {"request": Permission.GET_FEATURE_INFO.title, **_add_both(w1_l2)}, allow=False)

        # using multiple layers at the same time should validate all of them (all or nothing access)
        # order should not matter
        l11_l11 = ",".join([w1_l1, w1_l1])  # resolved as duplicate, only processed once, allowed
        l11_l12 = ",".join([w1_l1, w1_l2])  # W1-L1 is allowed, but not W1-L2, so both denied
        l11_l13 = ",".join([w1_l1, w1_l3])  # both are allowed, so full request allowed as well
        l12_l11 = ",".join([w1_l2, w1_l1])
        l13_l11 = ",".join([w1_l3, w1_l1])
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": l11_l11}, allow=True)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": l11_l12}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": l11_l13}, allow=True)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": l12_l11}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": l13_l11}, allow=True)

        # validate revoking access when explicit denies are placed under previously allowed-recursive resources
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w2_l1}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w2_l2}, allow=False)
        _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w2_l3}, allow=True)
        _test(w2_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w2_l1}, allow=False)
        _test(w2_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w2_l2}, allow=False)
        _test(w2_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": w2_l3}, allow=True)

        # mixing workspaces still work if only in scoped resource reference,
        # but fail for isolated path workspace due to mismatch workspace reference in at least one case
        #   Summary (GetFeature):
        #       L11: A  L21: D      -> only allowed combinations are exclusively with:  [L11, L13, L23]
        #       L12: D  L22: D      -> deny any combination when following are present: [L12, L21, L22]
        #       L13: A  L23: A
        for quantity in [2, 3, 4, 5]:
            layer_permutes = itertools.permutations([w1_l1, w1_l2, w1_l3, w2_l1, w2_l2, w2_l3], quantity)
            for layer_combo in layer_permutes:
                query = ",".join(layer_combo)
                allow_layer = not any(layer_deny in layer_combo for layer_deny in [w1_l2, w2_l1, w2_l2])
                _test(svc_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": query}, allow=allow_layer)

                # multiple layers nested under same workspace will work for request with Workspace isolated path
                # otherwise, automatic deny regardless if they were allowed during request without workspace in path
                allow_w1 = allow_layer and all(layer.startswith(w1_name) for layer in layer_combo)
                allow_w2 = allow_layer and all(layer.startswith(w2_name) for layer in layer_combo)
                _test(w1_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": query}, allow=allow_w1)
                _test(w2_wfs_path, {"request": Permission.GET_FEATURE.title, "typeNames": query}, allow=allow_w2)


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_SERVICES
@runner.MAGPIE_TEST_FUNCTIONAL
class TestServicesCachedSessionReconnect(ti.UserTestCase, ti.BaseTestCase):
    """
    Test detached session instances that can be caused by request caching to ensure they regain an active session.
    """
    __test__ = True

    @classmethod
    @utils.mocked_get_settings
    def setUpClass(cls):
        cls.version = __meta__.__version__
        cls.app = utils.get_test_magpie_app()
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.setup_admin()
        cls.test_service_type = ServiceAPI.service_type
        cls.test_service_name = "func-test-session-reconnect"
        cls.test_resource_type = models.Route.resource_type_name
        cls.test_group_name = "func-test-session-reconnect-group"
        cls.test_user_name = "func-test-session-user"

    @utils.mocked_get_settings
    def setUp(self):
        ti.UserTestCase.setUp(self)
        self.cookies = None
        self.headers, self.cookies = utils.check_or_try_login_user(self, self.usr, self.pwd, use_ui_form_submit=True)
        self.require = "cannot run tests without logged in user with '{}' permissions".format(self.grp)
        self.login_admin()

        # setup basic permissions on a resource for test user (in order to call effective resolution)
        utils.TestSetup.delete_TestService(self)
        utils.TestSetup.delete_TestGroup(self)
        res_id_list = utils.TestSetup.create_TestServiceResourceTree(self, resource_depth=4)
        self.test_service_id = res_id_list[0]
        test_res_with_perm_id = res_id_list[-2]
        self.test_resource_id = res_id_list[-1]
        # note: effective type define here to facilitate compare tests, does not matter for setup operations
        self.test_svc_perm = PermissionSet(Permission.READ, Access.ALLOW, Scope.RECURSIVE, PermissionType.EFFECTIVE)
        self.test_res_perm = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE, PermissionType.EFFECTIVE)
        utils.TestSetup.create_TestGroup(self)
        utils.TestSetup.create_TestGroupResourcePermission(
            self, override_resource_id=self.test_service_id, override_permission=self.test_svc_perm)
        utils.TestSetup.create_TestGroupResourcePermission(
            self, override_resource_id=test_res_with_perm_id, override_permission=self.test_res_perm)

        # prepare mock
        self.mock_call_count = 0

    def mock_detach_effective_permissions(
        self, service_self, user, resource, test_detach_items=None, real_effective_permissions=None, **kwargs
    ):
        self.mock_call_count += 1
        utils.check_val_true(not sa_inspect(user).detached, "Cannot run test. Not expected setup state.")
        utils.check_val_true(not sa_inspect(resource).detached, "Cannot run test. Not expected setup state.")
        utils.check_val_true(bool(test_detach_items), "Cannot run test. Missing what to disconnect!")
        utils.check_val_true(bool(test_detach_items), "Cannot run test. Real function not provided!")
        for item in test_detach_items:
            utils.check_val_is_in(item, ["user", "resource"], "Cannot run test. Unknown item to disconnect!")
            obj = user if item == "user" else resource
            session = obj.get_db_session()
            session.expunge(obj)
            utils.check_val_true(sa_inspect(obj).detached, "Cannot run test. Disconnect failed.")
        return real_effective_permissions(service_self, user, resource, **kwargs)

    def test_reconnect_user(self):
        real_effective_permissions = ServiceInterface.effective_permissions
        with mock.patch.object(
            ServiceInterface, "effective_permissions",
            new=lambda *_, **__: self.mock_detach_effective_permissions(
                *_, test_detach_items=["user"], real_effective_permissions=real_effective_permissions, **__
            )
        ):
            # if operation succeeds, detached objects succeeded dynamically reconnecting
            path = "/users/{}/resources/{}/permissions?effective=true"
            path = path.format(self.test_user_name, self.test_resource_id)
            resp = utils.test_request(self, "GET", path)
            body = utils.check_response_basic_info(resp)
            utils.check_val_equal(self.mock_call_count, 1)
            utils.check_val_is_in("permissions", body)
            perms = [PermissionSet(perm) for perm in body["permissions"]]
            perms = [perm for perm in perms if perm.name == Permission.READ]
            utils.check_val_equal(len(perms), 1)
            utils.check_all_equal(perms[0].json(), self.test_res_perm.json())

    def test_reconnect_resource(self):
        real_effective_permissions = ServiceInterface.effective_permissions
        with mock.patch.object(
            ServiceInterface, "effective_permissions",
            new=lambda *_, **__: self.mock_detach_effective_permissions(
                *_, test_detach_items=["resource"], real_effective_permissions=real_effective_permissions, **__
            )
        ):
            # if operation succeeds, detached objects succeeded dynamically reconnecting
            path = "/users/{}/resources/{}/permissions?effective=true"
            path = path.format(self.test_user_name, self.test_resource_id)
            resp = utils.test_request(self, "GET", path)
            body = utils.check_response_basic_info(resp)
            utils.check_val_equal(self.mock_call_count, 1)
            utils.check_val_is_in("permissions", body)
            perms = [PermissionSet(perm) for perm in body["permissions"]]
            perms = [perm for perm in perms if perm.name == Permission.READ]
            utils.check_val_equal(len(perms), 1)
            utils.check_all_equal(perms[0].json(), self.test_res_perm.json())
