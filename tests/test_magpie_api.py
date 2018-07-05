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
        assert json_body['authenticated'] is False
        assert 'group_names' not in json_body

    def test_GetVersion(self):
        resp = test_request(self.app, 'GET', '/version', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        assert json_body['version'] == magpie.__meta__.__version__


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
        assert 'db_version' in json_body
        assert 'version' in json_body
        assert json_body['version'] == magpie.__meta__.__version__

    @pytest.mark.users
    def test_GetUsers(self):
        resp = test_request(self.app, 'GET', '/users', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        assert 'user_names' in json_body.keys()
        assert len(json_body['user_names']) > 1         # should have more than only 'anonymous'
        assert 'anonymous' in json_body['user_names']   # anonymous always in users


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
        assert json_body['authenticated'] is False
        assert 'group_names' not in json_body

    def test_GetVersion(self):
        resp = test_request(self.url, 'GET', '/version', headers=self.json_headers)
        json_body = check_response_basic_info(resp, 200)
        assert 'db_version' in json_body
        assert 'version' in json_body
        assert json_body['version'] == magpie.__meta__.__version__


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
        cls.test_service_name = 'project-api'
        cls.test_service_type = cls.test_services_info[cls.test_service_name]['type']
        assert cls.test_service_type in cls.test_services_info

        resp = test_request(cls.url, 'GET', '/services/project-api', headers=cls.json_headers, cookies=cls.cookies)
        json_body = check_response_basic_info(resp, 200)
        cls.test_service_resource_id = json_body[cls.test_service_name]['resource_id']

        cls.test_resource_name = 'magpie-unittest-resource'
        test_service_resource_types = service_type_dict[cls.test_service_type].resource_types_permissions.keys()
        assert len(test_service_resource_types), "test service should allow at least 1 sub-resource for test execution"
        cls.test_resource_type = test_service_resource_types[0]

    def setUp(self):
        self.check_requirements()
        self.setup_DeleteTestResource()

    @pytest.mark.login
    def test_GetSession_Administrator(self):
        resp = test_request(self.url, 'GET', '/session', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        assert json_body['authenticated'] is True
        assert json_body['user_name'] == self.usr
        assert ADMIN_GROUP in json_body['group_names']
        assert 'user_email' in json_body

    @pytest.mark.users
    def test_GetUsers(self):
        resp = test_request(self.url, 'GET', '/users', headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        assert 'user_names' in json_body
        assert len(json_body['user_names']) > 1         # should have more than only 'anonymous'
        assert 'anonymous' in json_body['user_names']   # anonymous always in users
        assert self.usr in json_body['user_names']      # current test user in users

    @classmethod
    def check_GetUserResourcesPermissions(cls, user_name):
        route = '/users/{usr}/resources/{res_id}/permissions'.format(res_id=cls.test_service_resource_id, usr=user_name)
        resp = test_request(cls.url, 'GET', route, headers=cls.json_headers, cookies=cls.cookies)
        json_body = check_response_basic_info(resp, 200)
        assert 'permission_names' in json_body
        assert isinstance(json_body['permission_names'], list)

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
        assert 'group_names' in json_body
        assert isinstance(json_body['group_names'], list)
        assert ADMIN_GROUP in json_body['group_names']

    @pytest.mark.users
    def test_GetUserInheritedResources(self):
        route = '/users/{usr}/inherited_resources'.format(usr=self.usr)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        assert 'resources' in json_body
        assert isinstance(json_body['resources'], dict)
        assert all_equal(json_body['resources'].keys(), service_type_dict.keys(), any_order=True)
        for svc_type in json_body['resources']:
            for svc in json_body['resources'][svc_type]:
                svc_dict = json_body['resources'][svc_type][svc]
                assert 'resource_id' in svc_dict
                assert isinstance(svc_dict['resource_id'], int)
                assert 'service_name' in svc_dict
                assert isinstance(svc_dict['service_name'], six.string_types)
                assert 'service_url' in svc_dict
                assert isinstance(svc_dict['service_url'], six.string_types)
                assert 'service_type' in svc_dict
                assert isinstance(svc_dict['service_type'], six.string_types)
                assert 'public_url' in svc_dict
                assert isinstance(svc_dict['public_url'], six.string_types)
                assert 'permission_names' in svc_dict
                assert isinstance(svc_dict['permission_names'], list)
                assert 'resources' in svc_dict
                assert isinstance(svc_dict['resources'], dict)

    @pytest.mark.groups
    def test_GetGroupUsers(self):
        route = '/groups/{grp}/users'.format(grp=ADMIN_GROUP)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        assert 'user_names' in json_body
        assert isinstance(json_body['user_names'], list)
        assert ADMIN_USER in json_body['user_names']
        assert self.usr in json_body['user_names']

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
        assert cls.test_resource_name not in resources_names

    @classmethod
    def setup_DeleteTestResource(cls):
        resources = cls.setup_GetExistingTestServiceDirectResources()
        test_resource = filter(lambda r: r['resource_name'] == cls.test_resource_name, resources)
        # delete as required, skip if non-existing
        if len(test_resource) > 0:
            resource_id = test_resource[0]['resource_id']
            route = '/services/{svc}/resources/{res_id}'.format(svc=cls.test_service_name, res_id=resource_id)
            resp = test_request(cls.url, 'DELETE', route, headers=cls.json_headers, cookies=cls.cookies)
            assert resp.status_code == 200
        cls.setup_CheckNonExistingTestResource()

    @pytest.mark.services
    def test_GetServiceResources(self):
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        svc_dict = json_body[self.test_service_name]
        assert self.test_service_name in json_body
        assert isinstance(json_body[self.test_service_name], dict)

        assert 'resource_id' in svc_dict
        assert isinstance(svc_dict['resource_id'], int)
        assert 'service_name' in svc_dict
        assert isinstance(svc_dict['service_name'], six.string_types)
        assert 'service_url' in svc_dict
        assert isinstance(svc_dict['service_url'], six.string_types)
        assert 'service_type' in svc_dict
        assert isinstance(svc_dict['service_type'], six.string_types)
        assert 'public_url' in svc_dict
        assert isinstance(svc_dict['public_url'], six.string_types)
        assert 'permission_names' in svc_dict
        assert isinstance(svc_dict['permission_names'], list)
        assert 'resources' in svc_dict
        check_resource_children(svc_dict['resources'], svc_dict['resource_id'], svc_dict['resource_id'])

    @pytest.mark.services
    def test_PostServiceResources_DirectResource_NoParentID(self):
        self.setup_CheckNonExistingTestResource()

        resources_prior = self.setup_GetExistingTestServiceDirectResources()
        resources_prior_ids = [res['resource_id'] for res in resources_prior]

        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        resp = test_request(self.url, 'POST', route, headers=self.json_headers, cookies=self.cookies, json=data)
        json_body = check_response_basic_info(resp, 201)

        assert 'resource_id' in json_body
        assert json_body['resource_id'] not in resources_prior_ids
        assert 'resource_name' in json_body
        assert json_body['resource_name'] == self.test_resource_name
        assert 'resource_type' in json_body
        assert json_body['resource_type'] == self.test_resource_type

        self.setup_DeleteTestResource()

    @pytest.mark.services
    def test_PostServiceResources_DirectResource_WithParentID(self):
        self.setup_CheckNonExistingTestResource()

        resources_prior = self.setup_GetExistingTestServiceDirectResources()
        resources_prior_ids = [res['resource_id'] for res in resources_prior]
        service_id = self.setup_GetExistingTestServiceInfo()['resource_id']

        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": service_id
        }
        resp = test_request(self.url, 'POST', route, headers=self.json_headers, cookies=self.cookies, json=data)
        json_body = check_response_basic_info(resp, 201)

        assert 'resource_id' in json_body
        assert json_body['resource_id'] not in resources_prior_ids
        assert 'resource_name' in json_body
        assert json_body['resource_name'] == self.test_resource_name
        assert 'resource_type' in json_body
        assert json_body['resource_type'] == self.test_resource_type

        self.setup_DeleteTestResource()

    @pytest.mark.services
    def test_PostServiceResources_ChildrenResource_WithParentID(self):
        self.setup_CheckNonExistingTestResource()

        # create the direct resource
        route = '/services/{svc}/resources'.format(svc=self.test_service_name)
        data = {
            "resource_name": self.test_resource_name,
            "resource_type": self.test_resource_type,
        }
        resp = test_request(self.url, 'POST', route, headers=self.json_headers, cookies=self.cookies, json=data)
        json_body = check_response_basic_info(resp, 201)
        resources = self.setup_GetExistingTestServiceDirectResources()
        resources_ids = [res['resource_id'] for res in resources]
        test_resource_id = json_body['resource_id']
        assert test_resource_id in resources_ids, "service direct resource must exist to create children resource"

        # create the children resource under the direct resource and validate response info
        child_resource_name = self.test_resource_name + "-children"
        data = {
            "resource_name": child_resource_name,
            "resource_type": self.test_resource_type,
            "parent_id": test_resource_id
        }
        resp = test_request(self.url, 'POST', route, headers=self.json_headers, cookies=self.cookies, json=data)
        json_body = check_response_basic_info(resp, 201)
        assert 'resource_id' in json_body
        assert json_body['resource_id'] not in resources_ids
        assert 'resource_name' in json_body
        assert json_body['resource_name'] == child_resource_name
        assert 'resource_type' in json_body
        assert json_body['resource_type'] == self.test_resource_type

        # validate created children resource info
        service_root_id = self.setup_GetExistingTestServiceInfo()['resource_id']
        child_resource_id = json_body['resource_id']
        route = '/resources/{res_id}'.format(res_id=child_resource_id)
        resp = test_request(self.url, 'GET', route, headers=self.json_headers, cookies=self.cookies)
        json_body = check_response_basic_info(resp, 200)
        assert str(child_resource_id) in json_body
        resource_body = json_body[str(child_resource_id)]
        assert resource_body['root_service_id'] == service_root_id
        assert resource_body['parent_id'] == test_resource_id
        assert resource_body['resource_id'] == child_resource_id
        assert resource_body['resource_name'] == child_resource_name
        assert resource_body['resource_type'] == self.test_resource_type
        assert isinstance(resource_body['children'], dict)
        assert len(resource_body['children']) == 0

        self.setup_DeleteTestResource()


#    def test_PostServiceResources_DirectResource_Conflict(self):
#expected response body:
#{
#    "type": "application/json",
#    "code": 409,
#    "paramCompare": "[u'test44', u'test44a', u'4', u'5', u'6', u'7', u'8', u'9', u'10', u'11', u'12', u'13', u'14', u'15', u'16', u'17', u'24', u'25', u'26', u'27', u'28', u'29', u'30', u'31', u'32', u'33', u'34', u'35', u'36', u'38', u'41', u'42', u'43', u'44', u'51', u'52', u'53', u'55', u'59', u'test_david', u'test', u'Projects']",
#    "detail": "Resource name already exists at requested tree level for creation",
#    "param": "u'test'"
#}



if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
