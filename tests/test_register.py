#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_register
----------------------------------

Tests for `magpie.register` operations.
"""
import json
import shutil
import tempfile
import unittest

import mock

from magpie import register
from magpie.constants import get_constant
from magpie.db import get_db_session_from_settings
from magpie.permissions import Permission
from magpie.services import ServiceAPI
from magpie.utils import CONTENT_TYPE_JSON
from tests import runner, utils


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REGISTER
class TestRegister(unittest.TestCase):
    # pylint: disable=R0914

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
        # TODO: fix UI views so that they can be "found" directly in the WebTest.TestApp
        # NOTE: localhost magpie has to be running for following login call to work
        cls.headers, cls.cookies = utils.check_or_try_login_user(cls.app, cls.usr, cls.pwd,
                                                                 use_ui_form_submit=True, version=cls.version)
        cls.require = "cannot run tests without logged in user with '{}' permissions".format(cls.grp)

        cls.test_perm_svc_name = "test-service-perms-config"
        cls.test_perm_grp_name = "test-group-perms-config"

    def setUp(self):
        utils.TestSetup.delete_TestService(self, override_service_name=self.test_perm_svc_name)
        utils.TestSetup.delete_TestGroup(self, override_group_name=self.test_perm_grp_name)

    @classmethod
    def tearDownClass(cls):
        utils.TestSetup.delete_TestService(cls, override_service_name=cls.test_perm_svc_name)
        utils.TestSetup.delete_TestGroup(cls, override_group_name=cls.test_perm_grp_name)

    def test_register_providers(self):
        # TODO
        self.skipTest(reason="not implemented")

    def test_register_permissions_missing_group_create_new_entries(self):
        utils.TestSetup.create_TestService(self,
                                           override_service_name=self.test_perm_svc_name,
                                           override_service_type=ServiceAPI.service_type)
        utils.TestSetup.delete_TestGroup(self, override_group_name=self.test_perm_grp_name)
        session = get_db_session_from_settings(self.app.app.registry.settings)

        svc_perm = Permission.READ_MATCH
        res1_perm = Permission.READ
        res2_perm = Permission.WRITE
        res1_name = "test-resource"
        res2_name = "sub-test-resource"
        perm_config = {
            "permissions": [
                {
                    "service": self.test_perm_svc_name,
                    "permission": svc_perm.value,
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
        svc_res = body[self.test_perm_svc_name]["resources"]
        svc_res_id = body[self.test_perm_svc_name]["resource_id"]
        utils.check_val_is_in(res1_name, [svc_res[r]["resource_name"] for r in svc_res])
        res1_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res1_name][0]
        res1_sub = svc_res[str(res1_id)]["children"]
        utils.check_val_is_in(res2_name, [res1_sub[r]["resource_name"] for r in res1_sub])
        res2_id = [res1_sub[r]["resource_id"] for r in res1_sub if res1_sub[r]["resource_name"] == res2_name][0]

        # check that all permissions are created correctly
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, svc_res_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(svc_perm.value, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res1_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res1_perm.value, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res2_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(res2_perm.value, body["permission_names"])

    def test_register_permissions_existing_group_create_some_entries(self):
        utils.TestSetup.create_TestService(self,
                                           override_service_name=self.test_perm_svc_name,
                                           override_service_type=ServiceAPI.service_type)
        utils.TestSetup.create_TestGroup(self, override_group_name=self.test_perm_grp_name)
        session = get_db_session_from_settings(self.app.app.registry.settings)

        svc_perm = Permission.READ_MATCH
        res1_perm = Permission.READ
        res2_perm = Permission.WRITE
        res3_perm = Permission.WRITE_MATCH
        res1_name = "test-resource"
        res2_name = "sub-test-resource"
        res3_name = "sub-sub-test-resource"
        perm_config = {
            "permissions": [
                {
                    "service": self.test_perm_svc_name,
                    "permission": svc_perm.value,
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
                    "permission": res3_perm.value,
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
        svc_res = body[self.test_perm_svc_name]["resources"]
        svc_res_id = body[self.test_perm_svc_name]["resource_id"]
        utils.check_val_is_in(res1_name, [svc_res[r]["resource_name"] for r in svc_res])
        res1_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res1_name][0]
        res1_sub = svc_res[str(res1_id)]["children"]
        utils.check_val_is_in(res2_name, [res1_sub[r]["resource_name"] for r in res1_sub])
        res2_id = [res1_sub[r]["resource_id"] for r in res1_sub if res1_sub[r]["resource_name"] == res2_name][0]
        res2_sub = res1_sub[str(res2_id)]["children"]
        utils.check_val_is_in(res3_name, [res2_sub[r]["resource_name"] for r in res2_sub])
        res3_id = [res2_sub[r]["resource_id"] for r in res2_sub if res2_sub[r]["resource_name"] == res3_name][0]

        # check that all permissions are created correctly
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, svc_res_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_val_is_in(svc_perm.value, body["permission_names"])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res1_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_all_equal(body["permission_names"], [res1_perm.value])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res2_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_all_equal(body["permission_names"], [res2_perm.value])
        path = "/groups/{}/resources/{}/permissions".format(self.test_perm_grp_name, res3_id)
        resp = utils.test_request(self.app, "GET", path)
        body = utils.check_response_basic_info(resp)
        utils.check_all_equal(body["permission_names"], [res3_perm.value])

    def test_register_permissions_existing_group_without_intermediate_entries(self):
        utils.TestSetup.create_TestService(self,
                                           override_service_name=self.test_perm_svc_name,
                                           override_service_type=ServiceAPI.service_type)
        utils.TestSetup.create_TestGroup(self, override_group_name=self.test_perm_grp_name)
        session = get_db_session_from_settings(self.app.app.registry.settings)

        res1_name = "test-resource"
        res2_name = "sub-test-resource"
        res3_name = "sub-sub-test-resource"
        res3_perm = Permission.WRITE_MATCH
        perm_config = {
            "permissions": [
                {
                    "service": self.test_perm_svc_name,                         # exists
                    "resource": res1_name + "/" + res2_name + "/" + res3_name,  # none exist, all created for perm
                    "permission": res3_perm.value,                              # perm only to lowest child
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
        svc_res = body[self.test_perm_svc_name]["resources"]
        svc_res_id = body[self.test_perm_svc_name]["resource_id"]
        utils.check_val_is_in(res1_name, [svc_res[r]["resource_name"] for r in svc_res])
        res1_id = [svc_res[r]["resource_id"] for r in svc_res if svc_res[r]["resource_name"] == res1_name][0]
        res1_sub = svc_res[str(res1_id)]["children"]
        utils.check_val_is_in(res2_name, [res1_sub[r]["resource_name"] for r in res1_sub])
        res2_id = [res1_sub[r]["resource_id"] for r in res1_sub if res1_sub[r]["resource_name"] == res2_name][0]
        res2_sub = res1_sub[str(res2_id)]["children"]
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
        utils.check_all_equal(body["permission_names"], [res3_perm.value])

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
        assert config["providers"]["test-provider-1"]["url"] == "http://localhost-test/wps"
        assert config["providers"]["test-provider-2"]["url"] == "http://HOSTNAME/wps"

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
            perms = register._get_all_configs(tmp_dir, "permissions")  # pylint: disable=W0212
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
            perms = register._get_all_configs(tmp.name, "permissions")  # pylint: disable=W0212
        assert isinstance(perms, list) and len(perms) == 1 and isinstance(perms[0], list) and len(perms[0]) == 2
        assert perms[0][0]["perm"] == "permission1" and perms[0][1]["perm"] == "permission2"

    def test_get_all_config_from_dict(self):
        cfg = {"permissions": [{"perm": "permission1"}, {"perm": "permission2"}]}
        perms = register._get_all_configs(cfg, "permissions")  # pylint: disable=W0212
        assert isinstance(perms, list) and len(perms) == 1 and isinstance(perms[0], list) and len(perms[0]) == 2
        assert perms[0][0]["perm"] == "permission1" and perms[0][1]["perm"] == "permission2"


@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_REGISTER
def test_register_make_config_registry():
    assert register._make_config_registry(None, "whatever") == {}
    assert register._make_config_registry([], "whatever") == {}
    assert register._make_config_registry([{}], "whatever") == {}
    assert register._make_config_registry([None], "whatever") == {}  # noqa
    config = [{"key": "val1", "name": "name1"}, {"key": "val2"}]
    mapped = {"val1": {"key": "val1", "name": "name1"}, "val2": {"key": "val2"}}
    assert register._make_config_registry(config, "key") == mapped
