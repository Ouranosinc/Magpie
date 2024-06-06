#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_register
----------------------------------

Tests for `magpie.register` operations.
"""
import copy
import json
import os
import shutil
import tempfile
import unittest
from typing import TYPE_CHECKING

import mock
import six

from magpie import register
from magpie.constants import get_constant
from magpie.db import get_db_session_from_settings
from magpie.models import Directory
from magpie.permissions import Access, Permission, PermissionSet, Scope
from magpie.services import ServiceAPI, ServiceTHREDDS
from magpie.utils import CONTENT_TYPE_JSON
from tests import interfaces, runner, utils

if six.PY2:
    from backports import tempfile as tempfile2  # noqa  # pylint: disable=E0611,no-name-in-module  # Python 2
else:
    tempfile2 = tempfile  # pylint: disable=C0103,invalid-name

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.typedefs import JSON  # noqa: F401


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REGISTER
class TestRegister(interfaces.AdminTestCase, unittest.TestCase):
    # pylint: disable=R0914

    __test__ = True

    @classmethod
    def setUpClass(cls):
        cls.app = utils.get_test_magpie_app()
        cls.url = cls.app  # to simplify calls of TestSetup (all use .url)
        cls.grp = get_constant("MAGPIE_ADMIN_GROUP")
        cls.usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
        cls.pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
        cls.json_headers = utils.get_headers(cls.url, {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON})
        cls.cookies = None
        cls.version = utils.TestSetup.get_Version(cls)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)
        cls.setup_admin()

        cls.test_perm_svc_name = "test-service-perms-config"
        cls.test_perm_grp_name = "test-group-perms-config"

    def setUp(self):
        self.login_admin()
        utils.TestSetup.delete_TestService(self, override_service_name=self.test_perm_svc_name)
        utils.TestSetup.delete_TestGroup(self, override_group_name=self.test_perm_grp_name)

    def tearDown(self):
        self.cleanup()

    def test_register_providers(self):
        # TODO
        self.skipTest(reason="not implemented")

    def test_register_permissions_missing_group_create_new_entries(self):
        utils.TestSetup.create_TestService(self,
                                           override_service_name=self.test_perm_svc_name,
                                           override_service_type=ServiceAPI.service_type)
        utils.TestSetup.delete_TestGroup(self, override_group_name=self.test_perm_grp_name)
        session = get_db_session_from_settings(self.app.app.registry.settings)

        svc_perm = "read-match"  # using string for backward compatibility
        res1_perm = Permission.READ
        res2_perm = Permission.WRITE
        res3_perm = PermissionSet(Permission.READ, Access.DENY, Scope.RECURSIVE)
        res4_perm = PermissionSet(Permission.WRITE, Access.DENY, Scope.MATCH)
        res1_name = "test-resource"
        res2_name = "sub-test-resource"
        res3_name = "test-resource-json-fields"
        res4_name = "test-resource-str-explicit"
        perm_config = {
            "permissions": [
                {
                    "service": self.test_perm_svc_name,
                    "permission": svc_perm,
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
                {
                    "service": self.test_perm_svc_name,
                    "resource": res1_name,
                    "permission": res1_perm.value,
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
                {
                    "service": self.test_perm_svc_name,
                    "resource": res1_name + "/" + res2_name,
                    "permission": res2_perm.value,
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
                {
                    "service": self.test_perm_svc_name,
                    "resource": res3_name,
                    "permission": res3_perm.json(),
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
                {
                    "service": self.test_perm_svc_name,
                    "resource": res4_name,
                    "permission": str(res4_perm),
                    "action": "create",
                    "group": self.test_perm_grp_name,
                }
            ]
        }
        utils.check_no_raise(lambda: register.magpie_register_permissions_from_config(perm_config, db_session=session))

        # check that all service, resources, group are created correctly
        services = utils.TestSetup.get_RegisteredServicesList(self)
        utils.check_val_is_in(self.test_perm_svc_name, [s["service_name"] for s in services])
        groups = utils.TestSetup.get_RegisteredGroupsList(self)
        utils.check_val_is_in(self.test_perm_grp_name, groups)
        resp = utils.test_request(self.app, "GET", "/services/{}/resources".format(self.test_perm_svc_name))
        body = utils.check_response_basic_info(resp)
        svc_res = body[self.test_perm_svc_name]["resources"]  # type: JSON
        svc_res_id = body[self.test_perm_svc_name]["resource_id"]
        utils.check_val_is_in(res1_name, [svc_res[r]["resource_name"] for r in svc_res])
        res1_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res1_name][0]
        res3_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res3_name][0]
        res4_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res4_name][0]
        res1_sub = svc_res[str(res1_id)]["children"]  # type: JSON
        utils.check_val_is_in(res2_name, [res1_sub[r]["resource_name"] for r in res1_sub])
        res2_id = [res1_sub[r]["resource_id"] for r in res1_sub if res1_sub[r]["resource_name"] == res2_name][0]

        # check that all permissions are created correctly
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, svc_res_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(svc_perm, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res1_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res1_perm.value, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res2_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res2_perm.value, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res3_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(str(res3_perm), body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res4_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(str(res4_perm), body["permission_names"])

    def test_register_permissions_existing_group_create_some_entries(self):
        utils.TestSetup.create_TestService(self,
                                           override_service_name=self.test_perm_svc_name,
                                           override_service_type=ServiceAPI.service_type)
        utils.TestSetup.create_TestGroup(self, override_group_name=self.test_perm_grp_name)
        session = get_db_session_from_settings(self.app.app.registry.settings)

        svc_perm = "read-match"  # using string for backward compatibility
        res1_perm = Permission.READ
        res2_perm = Permission.WRITE
        res3_perm = "write-match"  # using string for backward compatibility
        res1_name = "test-resource"
        res2_name = "sub-test-resource"
        res3_name = "sub-sub-test-resource"
        perm_config = {
            "permissions": [
                {
                    "service": self.test_perm_svc_name,
                    "permission": svc_perm,
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
                {
                    "service": self.test_perm_svc_name,
                    "resource": res1_name,
                    "permission": res1_perm.value,
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
                {
                    "service": self.test_perm_svc_name,
                    "resource": res1_name + "/" + res2_name,
                    "permission": res2_perm.value,
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
                {
                    "service": self.test_perm_svc_name,
                    "resource": res1_name + "/" + res2_name + "/" + res3_name,
                    "permission": res3_perm,
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
            ]
        }
        utils.check_no_raise(lambda: register.magpie_register_permissions_from_config(perm_config, db_session=session))

        # check that all service, resources, group are created correctly
        services = utils.TestSetup.get_RegisteredServicesList(self)
        utils.check_val_is_in(self.test_perm_svc_name, [s["service_name"] for s in services])
        groups = utils.TestSetup.get_RegisteredGroupsList(self)
        utils.check_val_is_in(self.test_perm_grp_name, groups)
        resp = utils.test_request(self.app, "GET", "/services/{}/resources".format(self.test_perm_svc_name))
        body = utils.check_response_basic_info(resp)
        svc_res = body[self.test_perm_svc_name]["resources"]  # type: JSON
        svc_res_id = body[self.test_perm_svc_name]["resource_id"]
        utils.check_val_is_in(res1_name, [svc_res[r]["resource_name"] for r in svc_res])
        res1_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res1_name][0]
        res1_sub = svc_res[str(res1_id)]["children"]  # type: JSON
        utils.check_val_is_in(res2_name, [res1_sub[r]["resource_name"] for r in res1_sub])
        res2_id = [res1_sub[r]["resource_id"] for r in res1_sub if res1_sub[r]["resource_name"] == res2_name][0]
        res2_sub = res1_sub[str(res2_id)]["children"]  # type: JSON
        utils.check_val_is_in(res3_name, [res2_sub[r]["resource_name"] for r in res2_sub])
        res3_id = [res2_sub[r]["resource_id"] for r in res2_sub if res2_sub[r]["resource_name"] == res3_name][0]

        # check that all permissions are created correctly
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, svc_res_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(svc_perm, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res1_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res1_perm.value, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res2_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res2_perm.value, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res3_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res3_perm, body["permission_names"])

    def test_register_permissions_existing_group_without_intermediate_entries(self):
        utils.TestSetup.create_TestService(self,
                                           override_service_name=self.test_perm_svc_name,
                                           override_service_type=ServiceAPI.service_type)
        utils.TestSetup.create_TestGroup(self, override_group_name=self.test_perm_grp_name)
        session = get_db_session_from_settings(self.app.app.registry.settings)

        res1_name = "test-resource"
        res2_name = "sub-test-resource"
        res3_name = "sub-sub-test-resource"
        res3_perm = "write-match"  # using string for backward compatibility
        perm_config = {
            "permissions": [
                {
                    "service": self.test_perm_svc_name,                         # exists
                    "resource": res1_name + "/" + res2_name + "/" + res3_name,  # none exist, all created for perm
                    "permission": res3_perm,                                    # perm only on lowest child
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
            ]
        }
        utils.check_no_raise(lambda: register.magpie_register_permissions_from_config(perm_config, db_session=session))

        # check that all service, resources, group are created correctly
        services = utils.TestSetup.get_RegisteredServicesList(self)
        utils.check_val_is_in(self.test_perm_svc_name, [s["service_name"] for s in services])
        groups = utils.TestSetup.get_RegisteredGroupsList(self)
        utils.check_val_is_in(self.test_perm_grp_name, groups)
        resp = utils.test_request(self.app, "GET", "/services/{}/resources".format(self.test_perm_svc_name))
        body = utils.check_response_basic_info(resp)
        svc_res = body[self.test_perm_svc_name]["resources"]  # type: JSON
        svc_res_id = body[self.test_perm_svc_name]["resource_id"]
        utils.check_val_is_in(res1_name, [svc_res[r]["resource_name"] for r in svc_res])
        res1_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res1_name][0]
        res1_sub = svc_res[str(res1_id)]["children"]  # type: JSON
        utils.check_val_is_in(res2_name, [res1_sub[r]["resource_name"] for r in res1_sub])
        res2_id = [res1_sub[r]["resource_id"] for r in res1_sub if res1_sub[r]["resource_name"] == res2_name][0]
        res2_sub = res1_sub[str(res2_id)]["children"]  # type: JSON
        utils.check_val_is_in(res3_name, [res2_sub[r]["resource_name"] for r in res2_sub])
        res3_id = [res2_sub[r]["resource_id"] for r in res2_sub if res2_sub[r]["resource_name"] == res3_name][0]

        # check that all permissions are created correctly (only for final item)
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, svc_res_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_equal(body["permission_names"], [])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res1_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_equal(body["permission_names"], [])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res2_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_equal(body["permission_names"], [])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res3_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res3_perm, body["permission_names"])

    def test_register_permissions_multiple_resource_type_possible(self):
        """
        Verify that service that allows multiple resource-types children retrieves ``type`` field for their creation.
        """
        svc_type = ServiceTHREDDS.service_type
        svc_name = "unittest-service-thredds-register-children-resources"
        utils.TestSetup.create_TestService(self,
                                           override_service_name=svc_name,
                                           override_service_type=svc_type)
        utils.TestSetup.create_TestGroup(self, override_group_name=self.test_perm_grp_name)
        session = get_db_session_from_settings(self.app.app.registry.settings)

        res1_name = "test-resource"
        res2_name = "sub-test-resource"
        res3_name = "sub-sub-test-resource"
        res3_perm = "write-deny-recursive"
        res3_path = res1_name + "/" + res2_name + "/" + res3_name  # none exist, all created for final permission
        perm_config = {
            "permissions": [
                {
                    "service": svc_name,  # exists
                    "resource": res3_path,
                    "permission": res3_perm,  # perm only on lowest child
                    "type": Directory.resource_type_name,   # without this, fails because cannot infer Directory/File
                    "action": "create",
                    "group": self.test_perm_grp_name,
                },
            ]
        }
        utils.check_no_raise(
            lambda: register.magpie_register_permissions_from_config(perm_config, db_session=session))

        # check that all service, resources, group are created correctly
        services = utils.TestSetup.get_RegisteredServicesList(self)
        utils.check_val_is_in(svc_name, [s["service_name"] for s in services])
        groups = utils.TestSetup.get_RegisteredGroupsList(self)
        utils.check_val_is_in(self.test_perm_grp_name, groups)
        resp = utils.test_request(self.app, "GET", "/services/{}/resources".format(svc_name))
        body = utils.check_response_basic_info(resp)
        svc_res = body[svc_name]["resources"]  # type: JSON
        utils.check_val_is_in(res1_name, [svc_res[r]["resource_name"] for r in svc_res])
        res1_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res1_name][0]
        res1_sub = svc_res[str(res1_id)]["children"]  # type: JSON
        utils.check_val_is_in(res2_name, [res1_sub[r]["resource_name"] for r in res1_sub])
        res2_id = [res1_sub[r]["resource_id"] for r in res1_sub if res1_sub[r]["resource_name"] == res2_name][0]
        res2_sub = res1_sub[str(res2_id)]["children"]  # type: JSON
        utils.check_val_is_in(res3_name, [res2_sub[r]["resource_name"] for r in res2_sub])
        res3_id = [res2_sub[r]["resource_id"] for r in res2_sub if res2_sub[r]["resource_name"] == res3_name][0]

        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res3_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res3_perm, body["permission_names"])

        # validate that without the 'type', similar resource would not be created due to missing information
        res_missing_type_name = "missing-type"
        res_missing_type_path = res3_path.replace("/" + res3_name, "/" + res_missing_type_name)
        missing_type_perm_config = copy.deepcopy(perm_config)  # type: JSON
        missing_type_perm_config["permissions"][0].pop("type")
        missing_type_perm_config["permissions"][0]["resource"] = res_missing_type_path
        utils.check_no_raise(
            lambda: register.magpie_register_permissions_from_config(missing_type_perm_config, db_session=session))
        resp = utils.test_request(self.app, "GET", "/resources/{}".format(res2_id))
        body = utils.check_response_basic_info(resp)
        res_children = body["resource"]["children"]
        res_found = [res for _, res in res_children.items() if res["resource_name"] == res_missing_type_name]
        utils.check_val_equal(res_found, [])

    def test_variable_expansion_providers_config_style(self):
        providers_config = {
            "providers": {
                "${PROVIDER1}": {
                    "url": "http://${HOSTNAME}/wps"
                },
                "test-provider-2": {
                    "url": "http://HOSTNAME/wps"  # literal must not be expanded
                }
            }
        }
        env_override = {
            "PROVIDER1": "test-provider-1",
            "HOSTNAME": "localhost-test"
        }

        with mock.patch.dict("os.environ", env_override):
            config = register._expand_all(providers_config)  # pylint: disable=W0212
        print(config)
        assert all([k in ["test-provider-1", "test-provider-2"] for k in config["providers"]])
        assert "${PROVIDER1}" not in config["providers"]
        providers = config["providers"]  # type: JSON
        assert providers["test-provider-1"]["url"] == "http://localhost-test/wps"
        assert providers["test-provider-2"]["url"] == "http://HOSTNAME/wps"

    def test_variable_expansion_permissions_config_style(self):  # noqa: R0201
        permissions_config = {
            "permissions": [
                {
                    "service": "$TEST_SERVICE",
                    "resource": "/${TEST_RESOURCE}",
                    "user": "${TEST_USER}"
                },
                {
                    "service": "test-service-2",
                    "permission": "getcapabilities",
                    "group": "${MAGPIE_ADMIN_GROUP}"
                }
            ]
        }
        admins = get_constant("MAGPIE_ADMIN_GROUP")
        env_override = {
            "MAGPIE_ADMIN_GROUP": admins,
            "TEST_SERVICE": "test-service-1",
            "TEST_RESOURCE": "test-res",
            "TEST_USER": "user-test"
        }

        with mock.patch.dict("os.environ", env_override):
            config = register._expand_all(permissions_config)  # pylint: disable=W0212
        assert config["permissions"][0]["service"] == "test-service-1"
        assert config["permissions"][0]["resource"] == "/test-res"
        assert config["permissions"][0]["user"] == "user-test"
        assert config["permissions"][1]["service"] == "test-service-2"
        assert config["permissions"][1]["permission"] == "getcapabilities"
        assert config["permissions"][1]["group"] == admins

    def test_get_all_config_from_dir(self):
        tmp_dir = tempfile.mkdtemp()    # note: TemporaryDirectory doesn't exist until Python 3.2
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", dir=tmp_dir) as tmp1, \
             tempfile.NamedTemporaryFile(mode="w", suffix=".cfg", dir=tmp_dir) as tmp2:  # noqa: E127
            # format doesn't matter
            tmp1.write(json.dumps({"permissions": [{"perm": "permission1"}, {"perm": "permission2"}]}))
            tmp1.seek(0)  # back to start since file still open (auto-delete if closed)
            tmp2.write(json.dumps({"permissions": [{"perm": "permission3"}, {"perm": "permission4"}]}))
            tmp2.seek(0)  # back to start since file still open (auto-delete if closed)
            perms = register.get_all_configs(tmp_dir, "permissions")  # pylint: disable=W0212
        assert isinstance(perms, list) and len(perms) == 2 and all(isinstance(p, list) and len(p) == 2 for p in perms)
        # NOTE: order of file loading is not guaranteed
        assert ((perms[0][0]["perm"] == "permission1" and perms[0][1]["perm"] == "permission2" and
                 perms[1][0]["perm"] == "permission3" and perms[1][1]["perm"] == "permission4") or
                (perms[0][0]["perm"] == "permission3" and perms[0][1]["perm"] == "permission4" and
                 perms[1][0]["perm"] == "permission1" and perms[1][1]["perm"] == "permission2"))
        shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_get_all_config_from_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cfg") as tmp:
            # format doesn't matter
            tmp.write(json.dumps({"permissions": [{"perm": "permission1"}, {"perm": "permission2"}]}))
            tmp.seek(0)  # back to start since file still open (auto-delete if closed)
            perms = register.get_all_configs(tmp.name, "permissions")  # pylint: disable=W0212
        assert isinstance(perms, list) and len(perms) == 1 and isinstance(perms[0], list) and len(perms[0]) == 2
        assert perms[0][0]["perm"] == "permission1" and perms[0][1]["perm"] == "permission2"

    def test_get_all_config_from_dict(self):
        cfg = {"permissions": [{"perm": "permission1"}, {"perm": "permission2"}]}
        perms = register.get_all_configs(cfg, "permissions")  # pylint: disable=W0212
        assert isinstance(perms, list) and len(perms) == 1 and isinstance(perms[0], list) and len(perms[0]) == 2
        assert perms[0][0]["perm"] == "permission1" and perms[0][1]["perm"] == "permission2"


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REGISTER
def test_register_resolve_config_registry():
    # pylint: disable=C1803,W0212
    assert register._resolve_config_registry(None, "whatever") == {}
    assert register._resolve_config_registry([], "whatever") == {}
    assert register._resolve_config_registry([{}], "whatever") == {}
    assert register._resolve_config_registry([None], "whatever") == {}  # noqa
    config = [{"key": "val1", "name": "name1"}, {"key": "val2"}]
    mapped = {"val1": {"key": "val1", "name": "name1"}, "val2": {"key": "val2"}}
    assert register._resolve_config_registry(config, "key") == mapped  # type: ignore


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REGISTER
def test_register_process_permissions_from_multiple_files():
    """
    Validate that resolution using multiple configuration files retrieves definition across all of them.

    Use the *raw* format expected from loaded configuration files to validate their parsing at the same time.
    """
    cfg1 = {
        "users": [
            {"username": "usr1"},
            {"username": "usr2", "group": "grp2"},
            {"username": "usr3"}  # will be overridden
        ],
        "groups": [
            {"name": "grp1", "discoverable": True},
            {"name": "grp2"}
        ],
        "permissions": [
            {"permission": "perm1", "action": "remove", "service": "svc", "user": "y"},
            # applied to both user/group, default 'create' operation, group created with only string (no entry)
            {"permission": "perm2", "user": "x", "group": "grp3", "service": "svc"},
            # referenced group is a definition
            {"permission": "perm3", "action": "create", "service": "svc", "group": "grp1"}
        ]
    }
    cfg2 = {
        "permissions": [
            {"permission": "perm4", "group": "grp2"}  # referred from other file
        ],
        "users": [
            {"username": "usr3", "group": "grp3"}  # should override one in first config
        ]
    }

    with tempfile2.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "cfg1.json"), mode="w", encoding="utf-8") as cfg1_file:
            json.dump(cfg1, cfg1_file)
        with open(os.path.join(tmpdir, "cfg2.json"), mode="w", encoding="utf-8") as cfg2_file:
            json.dump(cfg2, cfg2_file)
        with utils.wrapped_call("magpie.register._process_permissions") as mock_process_perms:
            with utils.wrapped_call("magpie.register.get_admin_cookies", side_effect=lambda *_, **__: {}):
                register.magpie_register_permissions_from_config(tmpdir, settings={"magpie.url": "http://dontcare.com"})

    assert mock_process_perms.call_count == 2
    expect_users = {"usr1": cfg1["users"][0], "usr2": cfg1["users"][1], "usr3": cfg2["users"][0]}
    expect_groups = {"grp1": cfg1["groups"][0], "grp2": cfg1["groups"][1]}

    perms, _, _, users, groups, _ = mock_process_perms.call_args_list[0].args
    assert perms == cfg1["permissions"]
    assert users == expect_users
    assert groups == expect_groups

    perms, _, _, users, groups, _ = mock_process_perms.call_args_list[1].args
    assert perms == cfg2["permissions"]
    assert users == expect_users
    assert groups == expect_groups
