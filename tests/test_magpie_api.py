#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_api
----------------------------------

Tests for `magpie.api` module.
"""

import unittest
import pytest
import pyramid.testing
import six
import yaml
from magpie import *
from magpie.services import service_type_dict
from magpie import magpie
from test_utils import *


@pytest.mark.offline
@pytest.mark.api
class TestMagpieAPI_NoAuthLocal(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.json_headers = [('Content-Type', 'application/json')]

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    def test_GetSession_Anonymous(self):
        resp = test_request(self.app, 'GET', '/session', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_equal(json_body['authenticated'], False)
        check_val_not_in('group_names', json_body)

    def test_GetVersion(self):
        resp = test_request(self.app, 'GET', '/version', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('db_version', json_body)
        check_val_is_in('version', json_body)
        check_val_equal(json_body['version'], magpie.__meta__.__version__)


@pytest.mark.skip(reason="Not implemented.")
@pytest.mark.offline
@pytest.mark.api
class TestMagpieAPI_WithUsersAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'Users' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()


@unittest.skip("Signin not working, cannot test protected paths.")
@pytest.mark.offline
@pytest.mark.api
class TestMagpieAPI_WithAdminAuthLocal(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = get_test_magpie_app()
        cls.usr = os.getenv('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = os.getenv('MAGPIE_TEST_ADMIN_PASSWORD')
        assert cls.usr and cls.pwd, "cannot login with unspecified username/password"
        cls.headers, cls.cookies = check_or_try_login_user(cls.app, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(ADMIN_GROUP)
        assert cls.headers and cls.cookies, cls.require
        cls.app.cookies = cls.cookies
        cls.json_headers = [('Content-Type', 'application/json')]

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = check_or_try_login_user(cls.app, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies and cls.app.cookies, cls.require

    def setUp(self):
        self.check_requirements()

    def test_GetAPI(self):
        resp = test_request(self.app, 'GET', '/__api__', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('db_version', json_body)
        check_val_is_in('version', json_body)
        check_val_equal(json_body['version'], magpie.__meta__.__version__)
        check_val_type(json_body['version'], types.StringTypes)
        version_parts = json_body['version'].split('.')
        check_val_equal(len(version_parts), 3)

    @pytest.mark.users
    def test_GetUsers(self):
        resp = test_request(self.app, 'GET', '/users', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('user_names', json_body)
        check_val_is_in('anonymous', json_body['user_names'])       # anonymous always in users
        check_val_equal(len(json_body['user_names']) > 1, True)     # should have more than only 'anonymous'


@pytest.mark.online
@pytest.mark.api
class TestMagpieAPI_NoAuthRemote(unittest.TestCase):
    """
    Test any operation that do not require user AuthN/AuthZ.
    """

    @classmethod
    def setUpClass(cls):
        cls.url = os.getenv('MAGPIE_TEST_REMOTE_SERVER_URL')
        assert cls.url, "cannot test without a remote server URL"
        cls.json_headers = {'Content-Type': 'application/json'}

    @classmethod
    def tearDownClass(cls):
        pyramid.testing.tearDown()

    @pytest.mark.login
    def test_GetSession_Anonymous(self):
        resp = test_request(self.url, 'GET', '/session', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_equal(json_body['authenticated'], False)
        check_val_not_in('group_names', json_body)

    def test_GetVersion(self):
        resp = test_request(self.url, 'GET', '/version', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('db_version', json_body)
        check_val_is_in('version', json_body)
        # server not necessarily at latest version, ensure at least format
        #check_val_equal(json_body['version'], magpie.__meta__.__version__)
        check_val_type(json_body['version'], types.StringTypes)
        version_parts = json_body['version'].split('.')
        check_val_equal(len(version_parts), 3)


@pytest.mark.online
@pytest.mark.api
class TestMagpieAPI_WithAdminAuthRemote(unittest.TestCase):
    """
    Test any operation that require at least 'Administrator' group AuthN/AuthZ.
    Use an already running remote bird server.
    """

    @classmethod
    def setUpClass(cls):
        cls.usr = os.getenv('MAGPIE_TEST_ADMIN_USERNAME')
        cls.pwd = os.getenv('MAGPIE_TEST_ADMIN_PASSWORD')
        cls.url = os.getenv('MAGPIE_TEST_REMOTE_SERVER_URL')
        assert cls.url, "cannot test without a remote server URL"
        assert cls.usr and cls.pwd, "cannot login with unspecified username/password"
        cls.headers, cls.cookies = check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        cls.require = "cannot run tests without logged in '{}' user".format(ADMIN_GROUP)
        cls.json_headers = {'Content-Type': 'application/json'}
        cls.check_requirements()
        cls.get_test_values()

    @classmethod
    def tearDownClass(cls):
        cls.setup_DeleteTestServiceResource()
        pyramid.testing.tearDown()

    @classmethod
    def check_requirements(cls):
        headers, cookies = check_or_try_login_user(cls.url, cls.usr, cls.pwd)
        assert headers and cookies, cls.require
        assert cls.headers and cls.cookies, cls.require

    @classmethod
    def get_test_values(cls):
        services_cfg = yaml.load(open(MAGPIE_PROVIDERS_CONFIG_PATH, 'r'))
        cls.test_services_info = services_cfg['providers']
        cls.test_service_name = u'project-api'
        cls.test_service_type = cls.test_services_info[cls.test_service_name]['type']
        check_val_is_in(cls.test_service_type, cls.test_services_info)

        resp = test_request(cls.url, 'GET', '/services/project-api', headers=cls.json_headers, cookies=cls.cookies)
        json_body = check_response_basic_info(resp, 200)
        cls.test_service_resource_id = json_body[cls.test_service_name]['resource_id']

        cls.test_resource_name = u'magpie-unittest-resource'
        test_service_resource_types = service_type_dict[cls.test_service_type].resource_types_permissions.keys()
        assert len(test_service_resource_types), "test service should allow at least 1 sub-resource for test execution"
        cls.test_resource_type = test_service_resource_types[0]

        resp = test_request(cls.url, 'GET', '/version', headers=cls.json_headers, cookies=cls.cookies)
        json_body = check_response_basic_info(resp, 200)
        cls.version = json_body['version']

    def setUp(self):
        self.check_requirements()
        self.setup_DeleteTestServiceResource()

    @pytest.mark.login
    def test_GetSession_Administrator(self):
        resp = test_request(self.url, 'GET', '/session', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_equal(json_body['authenticated'], True)
        check_val_equal(json_body['user_name'], self.usr)
        check_val_is_in(ADMIN_GROUP, json_body['group_names'])
        check_val_type(json_body['group_names'], list)
        check_val_is_in('user_email', json_body)

    @pytest.mark.users
    def test_GetUsers(self):
        resp = test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('user_names', json_body)
        check_val_type(json_body['user_names'], list)
        check_val_equal(len(json_body['user_names']) > 1, True)     # should have more than only 'anonymous'
        check_val_is_in('anonymous', json_body['user_names'])       # anonymous always in users
        check_val_is_in(self.usr, json_body['user_names'])          # current test user in users

    @classmethod
    def check_GetUserResourcesPermissions(cls, user_name):
        route = '/users/{usr}/resources/{res_id}/permissions'.format(res_id=cls.test_service_resource_id, usr=user_name)
        resp = test_request(cls.url, 'GET', route, headers=cls.json_headers, cookies=cls.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('permission_names', json_body)
        check_val_type(json_body['permission_names'], list)

    @pytest.mark.users
    def test_GetCurrentUserResourcesPermissions(self):
        self.check_GetUserResourcesPermissions('current')

    @pytest.mark.users
    def test_GetUserResourcesPermissions(self):
        self.check_GetUserResourcesPermissions(self.usr)

    @pytest.mark.users
    def test_GetCurrentUserGroups(self):
        resp = test_request(self.url, 'GET', '/users/current/groups', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('group_names', json_body)
        check_val_type(json_body['group_names'], list)
        check_val_is_in(ADMIN_GROUP, json_body['group_names'])

    @pytest.mark.users
    def test_GetUserInheritedResources(self):
        route = '/users/{usr}/inherited_resources'.format(usr=self.usr)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('resources', json_body)
        check_val_type(json_body['resources'], dict)
        check_all_equal(json_body['resources'].keys(), service_type_dict.keys(), any_order=True)
        for svc_type in json_body['resources']:
            for svc in json_body['resources'][svc_type]:
                svc_dict = json_body['resources'][svc_type][svc]
                check_val_type(svc_dict, dict)
                check_val_is_in('resource_id', svc_dict)
                check_val_is_in('service_name', svc_dict)
                check_val_is_in('service_type', svc_dict)
                check_val_is_in('service_url', svc_dict)
                check_val_is_in('public_url', svc_dict)
                check_val_is_in('permission_names', svc_dict)
                check_val_is_in('resources', svc_dict)
                check_val_type(svc_dict['resource_id'], int)
                check_val_type(svc_dict['service_name'], types.StringTypes)
                check_val_type(svc_dict['service_url'], types.StringTypes)
                check_val_type(svc_dict['service_type'], types.StringTypes)
                check_val_type(svc_dict['public_url'], types.StringTypes)
                check_val_type(svc_dict['permission_names'], list)
                check_val_type(svc_dict['resources'], dict)

    @pytest.mark.groups
    def test_GetGroupUsers(self):
        route = '/groups/{grp}/users'.format(grp=ADMIN_GROUP)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in('user_names', json_body)
        check_val_type(json_body['user_names'], list)
        check_val_is_in(ADMIN_USER, json_body['user_names'])
        check_val_is_in(self.usr, json_body['user_names'])

    @classmethod
    def setup_GetExistingTestServiceInfo(cls):
        route = '/services/{svc}'.format(svc=cls.test_service_name)
        resp = test_request(cls.url, 'GET', route, headers=cls.json_headers, cookies=cls.cookies)
        return resp.json()[cls.test_service_name]

    @classmethod
    def setup_GetExistingTestServiceDirectResources(cls):
        route = '/services/{svc}/resources'.format(svc=cls.test_service_name)
        resp = test_request(cls.url, 'GET', route, headers=cls.json_headers, cookies=cls.cookies)
        json_body = resp.json()
        resources = json_body[cls.test_service_name]['resources']
        return [resources[res] for res in resources]

    @classmethod
    def setup_CheckNonExistingTestResource(cls):
        resources = cls.setup_GetExistingTestServiceDirectResources()
        resources_names = [res['resource_name'] for res in resources]
        check_val_not_in(cls.test_resource_name, resources_names)

    @classmethod
    def setup_CreateTestServiceResource(cls, data_override=None):
        route = '/services/{svc}/resources'.format(svc=cls.test_service_name)
        data = {
            "resource_name": cls.test_resource_name,
            "resource_type": cls.test_resource_type,
        }
        if data_override:
            data.update(data_override)
        resp = test_request(cls.url, 'POST', route, headers=cls.json_headers, cookies=cls.cookies, json=data)
        return check_response_basic_info(resp, 201)

    @classmethod
    def setup_DeleteTestServiceResource(cls):
        resources = cls.setup_GetExistingTestServiceDirectResources()
        test_resource = filter(lambda r: r['resource_name'] == cls.test_resource_name, resources)
        # delete as required, skip if non-existing
        if len(test_resource) > 0:
            resource_id = test_resource[0]['resource_id']
            route = '/services/{svc}/resources/{res_id}'.format(svc=cls.test_service_name, res_id=resource_id)
            resp = test_request(cls.url, 'DELETE', route, headers=cls.json_headers, cookies=cls.cookies)
            check_val_equal(resp.status_code, 200)
        cls.setup_CheckNonExistingTestResource()

    @pytest.mark.services
    def test_GetServiceResources(self):
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        svc_dict = json_body[self.test_service_name]
        check_val_is_in(self.test_service_name, json_body)
        check_val_type(json_body[self.test_service_name], dict)
        check_val_is_in('resource_id', svc_dict)
        check_val_is_in('service_name', svc_dict)
        check_val_is_in('service_type', svc_dict)
        check_val_is_in('service_url', svc_dict)
        check_val_is_in('public_url', svc_dict)
        check_val_is_in('permission_names', svc_dict)
        check_val_is_in('resources', svc_dict)
        check_val_type(svc_dict['resource_id'], int)
        check_val_type(svc_dict['service_name'], types.StringTypes)
        check_val_type(svc_dict['service_url'], types.StringTypes)
        check_val_type(svc_dict['service_type'], types.StringTypes)
        check_val_type(svc_dict['public_url'], types.StringTypes)
        check_val_type(svc_dict['permission_names'], list)
        check_resource_children(svc_dict['resources'], svc_dict['resource_id'], svc_dict['resource_id'])

    @pytest.mark.services
    def test_PostServiceResources_DirectResource_NoParentID(self):
        resources_prior = self.setup_GetExistingTestServiceDirectResources()
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        json_body = self.setup_CreateTestServiceResource()
        check_val_is_in('resource_id', json_body)
        check_val_is_in('resource_name', json_body)
        check_val_is_in('resource_type', json_body)
        check_val_not_in(json_body['resource_id'], resources_prior_ids)
        check_val_equal(json_body['resource_name'], self.test_resource_name)
        check_val_equal(json_body['resource_type'], self.test_resource_type)

    @pytest.mark.services
    def test_PostServiceResources_DirectResource_WithParentID(self):
        resources_prior = self.setup_GetExistingTestServiceDirectResources()
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        service_id = self.setup_GetExistingTestServiceInfo()['resource_id']
        extra_data = {"parent_id": service_id}
        json_body = self.setup_CreateTestServiceResource(extra_data)
        check_val_is_in('resource_id', json_body)
        check_val_is_in('resource_name', json_body)
        check_val_is_in('resource_type', json_body)
        check_val_not_in(json_body['resource_id'], resources_prior_ids)
        check_val_equal(json_body['resource_name'], self.test_resource_name)
        check_val_equal(json_body['resource_type'], self.test_resource_type)

    @pytest.mark.services
    def test_PostServiceResources_ChildrenResource_WithParentID(self):
        # create the direct resource
        json_body = self.setup_CreateTestServiceResource()
        resources = self.setup_GetExistingTestServiceDirectResources()
        resources_ids = [res['resource_id'] for res in resources]
        test_resource_id = json_body['resource_id']
        check_val_is_in(test_resource_id, resources_ids, msg="service resource must exist to create children resource")

        # create the children resource under the direct resource and validate response info
        child_resource_name = self.test_resource_name + "-children"
        data_override = {
            "resource_name": child_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": test_resource_id
        }
        json_body = self.setup_CreateTestServiceResource(data_override)
        check_val_is_in('resource_id', json_body)
        check_val_not_in(json_body['resource_id'], resources_ids)
        check_val_is_in('resource_name', json_body)
        check_val_equal(json_body['resource_name'], child_resource_name)
        check_val_is_in('resource_type', json_body)
        check_val_equal(json_body['resource_type'], self.test_resource_type)

        # validate created children resource info
        service_root_id = self.setup_GetExistingTestServiceInfo()['resource_id']
        child_resource_id = json_body['resource_id']
        route = '/resources/{res_id}'.format(res_id=child_resource_id)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        check_val_is_in(str(child_resource_id), json_body)
        resource_body = json_body[str(child_resource_id)]
        check_val_equal(resource_body['root_service_id'], service_root_id)
        check_val_equal(resource_body['parent_id'], test_resource_id)
        check_val_equal(resource_body['resource_id'], child_resource_id)
        check_val_equal(resource_body['resource_name'], child_resource_name)
        check_val_equal(resource_body['resource_type'], self.test_resource_type)
        check_val_type(resource_body['children'], dict)
        check_val_equal(len(resource_body['children']), 0)

    @pytest.mark.services
    def test_PostServiceResources_DirectResource_Conflict(self):
        self.setup_CreateTestServiceResource()
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        data = {"resource_name": self.test_resource_name, "resource_type": self.test_resource_type}
        resp = test_request(self.url, 'POST', route, headers=self.json_headers, cookies=self.cookies, json=data)
        json_body = check_response_basic_info(resp, 409)
        check_error_param_structure(json_body, version=self.version,
                                    isParamValueLiteralUnicode=True, paramCompareExists=True,
                                    paramValue=self.test_resource_name, paramName=u'resource_name')

    @pytest.mark.resources
    def test_PostResources_DirectServiceResource(self):
        service_info = self.setup_GetExistingTestServiceInfo()
        service_resource_id = service_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": service_resource_id
        }
        resp = test_request(self.url, 'POST', '/resources', headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = check_response_basic_info(resp, 201)
        check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type, self.version)

    @pytest.mark.resources
    def test_PostResources_ChildrenResource(self):
        resource_info = self.setup_CreateTestServiceResource()
        direct_resource_id = resource_info['resource_id']

        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": direct_resource_id
        }
        resp = test_request(self.url, 'POST', '/resources', headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = check_response_basic_info(resp, 201)
        check_post_resource_structure(json_body, self.test_resource_name, self.test_resource_type, self.version)

    @pytest.mark.resources
    def test_PostResources_MissingParentID(self):
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        resp = test_request(self.url, 'POST', '/resources', headers=self.json_headers, cookies=self.cookies, data=data)
        json_body = check_response_basic_info(resp, 422)
        check_error_param_structure(json_body, paramName='parent_id', paramValue=repr(None), version=self.version)

    @pytest.mark.resources
    def test_DeleteResource(self):
        json_body = self.setup_CreateTestServiceResource()
        resource_id = json_body['resource_id']

        route = '/resources/{res_id}'.format(res_id=resource_id)
        resp = test_request(self.url, 'DELETE', route, headers=self.json_headers, cookies=self.cookies)
        check_response_basic_info(resp, 200)
        self.setup_CheckNonExistingTestResource()


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
