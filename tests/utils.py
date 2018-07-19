import six
import pyramid
import requests
from distutils.version import *
from webtest import TestApp
from webtest.response import TestResponse
import magpie
from magpie import __meta__, db, models, services, magpiectl, MAGPIE_INI_FILE_PATH


def config_setup_from_ini(config_ini_file_path):
    settings = db.get_settings_from_config_ini(config_ini_file_path)
    config = pyramid.testing.setUp(settings=settings)
    return config


def get_test_magpie_app():
    # parse settings from ini file to pass them to the application
    config = config_setup_from_ini(MAGPIE_INI_FILE_PATH)
    # required redefinition because root models' location is not the same from within this test file
    config.add_settings({'ziggurat_foundations.model_locations.User': 'models:User',
                         'ziggurat_foundations.model_locations.user': 'models:User'})
    config.include('ziggurat_foundations.ext.pyramid.sign_in')
    # remove API which cause duplicate view errors (?) TODO: figure out why it does so, because it shouldn't
    config.registry.settings['magpie.api_generation_disabled'] = True
    config.registry.settings['magpie.db_migration_disabled'] = True
    # scan dependencies
    config.include('magpie')
    config.scan('magpie')
    # create the test application
    app = TestApp(magpiectl.main({}, **config.registry.settings))
    return app


def get_headers_content_type(app_or_url, content_type):
    if isinstance(app_or_url, TestApp):
        return [('Content-Type', content_type)]
    return {'Content-Type': content_type}


def get_response_content_types_list(response):
    return [ct.strip() for ct in response.headers['Content-Type'].split(';')]


def get_service_types_for_version(version):
    available_service_types = set(services.service_type_dict.keys())
    if LooseVersion(version) <= LooseVersion('0.6.2'):
        available_service_types = available_service_types - {'access'}
    return list(available_service_types)


def test_request(app_or_url, method, path, timeout=5, allow_redirects=True, **kwargs):
    """
    Calls the request using either a `webtest.TestApp` instance or a `requests` instance from a string URL.
    :param app_or_url: `webtest.TestApp` instance of the test application or remote server URL to call with `requests`
    :param method: request method (GET, POST, PUT, DELETE)
    :param path: test path starting at base path
    :return: response of the request
    """
    method = method.upper()

    # obtain json body from any json/data/body/params kw and empty {} if not specified
    # reapply with the expected webtest/requests method kw afterward
    json_body = None
    for kw in ['json', 'data', 'body', 'params']:
        json_body = kwargs.get(kw, json_body)
        if kw in kwargs:
            kwargs.pop(kw)
    json_body = json_body or {}

    if isinstance(app_or_url, TestApp):
        # remove any 'cookies' keyword handled by the 'TestApp' instance
        if 'cookies' in kwargs:
            cookies = kwargs.pop('cookies')
            if cookies and not app_or_url.cookies:
                app_or_url.cookies.update(cookies)

        kwargs['params'] = json_body
        if method == 'GET':
            return app_or_url.get(path, **kwargs)
        elif method == 'POST':
            return app_or_url.post_json(path, **kwargs)
        elif method == 'PUT':
            return app_or_url.put_json(path, **kwargs)
        elif method == 'DELETE':
            return app_or_url.delete_json(path, **kwargs)
    else:
        kwargs['json'] = json_body
        url = '{url}{path}'.format(url=app_or_url, path=path)
        return requests.request(method, url, timeout=timeout, allow_redirects=allow_redirects, **kwargs)


def check_or_try_login_user(app_or_url, username=None, password=None, headers=None):
    """
    Verifies that the required user is already logged in (or none is if username=None), or tries to login him otherwise.

    :param app_or_url: `webtest.TestApp` instance of the test application or remote server URL to call with `requests`
    :param username: name of the user to login or None otherwise
    :param password: password to use for login if the user was not already logged in
    :param headers: headers to include in the test request
    :return: headers and cookies of the user session or (None, None)
    :raise: Exception on any login/logout failure as required by the caller's specifications (username/password)
    """

    headers = headers or {}

    if isinstance(app_or_url, TestApp):
        resp = app_or_url.get('/session', headers=headers)
        body = resp.json
    else:
        resp = requests.get('{}/session'.format(app_or_url), headers=headers)
        body = resp.json()

    if resp.status_code != 200:
        raise Exception('cannot retrieve logged in user information')

    auth = body.get('authenticated', False)
    user = body.get('user_name', '')
    if auth is False and username is None:
        return None, None
    if auth is False and username is not None:
        data = {'user_name': username, 'password': password, 'provider_name': 'ziggurat'}

        if isinstance(app_or_url, TestApp):
            resp = app_or_url.post_json('/signin', data, headers=headers)
        else:
            resp = requests.post('{}/signin'.format(app_or_url), json=data, headers=headers)

        if resp.status_code == 200:
            return resp.headers, resp.cookies
        return None, None

    if auth is True and username != user:
        raise Exception("invalid user")


def format_test_val_ref(val, ref, pre='Fail'):
    return '({0}) Test value: `{1}`, Reference value: `{2}`'.format(pre, val, ref)


def all_equal(iter_val, iter_ref, any_order=False):
    if not (hasattr(iter_val, '__iter__') and hasattr(iter_ref, '__iter__')):
        return False
    if len(iter_val) != len(iter_ref):
        return False
    if any_order:
        return all([it in iter_ref for it in iter_val])
    return all(it == ir for it, ir in zip(iter_val, iter_ref))


def check_all_equal(iter_val, iter_ref, any_order=False, msg=None):
    r_it_val = repr(iter_val)
    r_it_ref = repr(iter_ref)
    assert all_equal(iter_val, iter_ref, any_order), msg or format_test_val_ref(r_it_val, r_it_ref, pre='Equal Fail')


def check_val_equal(val, ref, msg=None):
    assert isinstance(ref, null) or val == ref, msg or format_test_val_ref(val, ref, pre='Equal Fail')


def check_val_not_equal(val, ref, msg=None):
    assert isinstance(ref, null) or val != ref, msg or format_test_val_ref(val, ref, pre='Equal Fail')


def check_val_is_in(val, ref, msg=None):
    assert isinstance(ref, null) or val in ref, msg or format_test_val_ref(val, ref, pre='Is In Fail')


def check_val_not_in(val, ref, msg=None):
    assert isinstance(ref, null) or val not in ref, msg or format_test_val_ref(val, ref, pre='Not In Fail')


def check_val_type(val, ref, msg=None):
    assert isinstance(val, ref), msg or format_test_val_ref(val, repr(ref), pre='Type Fail')


def check_response_basic_info(response, expected_code=200):
    """
    Validates basic Magpie API response metadata.
    :param response: response to validate.
    :param expected_code: status code to validate from the response.
    :return: json body of the response for convenience.
    """
    if isinstance(response, TestResponse):
        json_body = response.json
    else:
        json_body = response.json()
    content_types = get_response_content_types_list(response)
    check_val_is_in('application/json', content_types)
    check_val_equal(response.status_code, expected_code)
    check_val_equal(json_body['code'], expected_code)
    check_val_equal(json_body['type'], 'application/json')
    assert json_body['detail'] != ''
    return json_body


class null(object):
    """ Represents a null value to differentiate from None. """
    def __repr__(self):
        return '<Null>'


Null = null()


def check_error_param_structure(json_body, paramValue=Null, paramName=Null, paramCompare=Null,
                                isParamValueLiteralUnicode=False, paramCompareExists=False, version=None):
    """
    Validates error response 'param' information based on different Magpie version formats.
    :param json_body: json body of the response to validate.
    :param paramValue: expected 'value' of param, not verified if <Null>
    :param paramName: expected 'name' of param, not verified if <Null> or non existing for Magpie version
    :param paramCompare: expected 'compare'/'paramCompare' value, not verified if <Null>
    :param isParamValueLiteralUnicode: param value is represented as `u'{paramValue}'` for older Magpie version
    :param paramCompareExists: verify that 'compare'/'paramCompare' is in the body, not necessarily validating the value
    :param version: version of application/remote server to use for format validation, use local Magpie version if None
    :raise failing condition
    """
    check_val_type(json_body, dict)
    check_val_is_in('param', json_body)
    version = version or __meta__.__version__
    if LooseVersion(version) >= LooseVersion('0.6.3'):
        check_val_type(json_body['param'], dict)
        check_val_is_in('value', json_body['param'])
        check_val_is_in('name', json_body['param'])
        check_val_equal(json_body['param']['name'], paramName)
        check_val_equal(json_body['param']['value'], paramValue)
        if paramCompareExists:
            check_val_is_in('compare', json_body['param'])
            check_val_equal(json_body['param']['compare'], paramCompare)
    else:
        # unicode representation was explicitly returned in value only when of string type
        if isParamValueLiteralUnicode and isinstance(paramValue, six.string_types):
            paramValue = u'u\'{}\''.format(paramValue)
        check_val_equal(json_body['param'], paramValue)
        if paramCompareExists:
            check_val_is_in('paramCompare', json_body)
            check_val_equal(json_body['paramCompare'], paramCompare)


def check_post_resource_structure(json_body, resource_name, resource_type, version=None):
    """
    Validates POST /resource response information based on different Magpie version formats.
    :param json_body: json body of the response to validate.
    :param resource_name: name of the resource to validate.
    :param resource_type: type of the resource to validate.
    :param version: version of application/remote server to use for format validation, use local Magpie version if None.
    :raise failing condition
    """
    version = version or __meta__.__version__
    if LooseVersion(version) >= LooseVersion('0.6.3'):
        check_val_is_in('resource', json_body)
        check_val_type(json_body['resource'], dict)
        check_val_is_in('resource_name', json_body['resource'])
        check_val_is_in('resource_type', json_body['resource'])
        check_val_is_in('resource_id', json_body['resource'])
        check_val_equal(json_body['resource']['resource_name'], resource_name)
        check_val_equal(json_body['resource']['resource_name'], resource_type)
        check_val_type(json_body['resource']['resource_id'], int)
    else:
        check_val_is_in('resource_name', json_body)
        check_val_is_in('resource_type', json_body)
        check_val_is_in('resource_id', json_body)
        check_val_equal(json_body['resource_name'], resource_name)
        check_val_equal(json_body['resource_type'], resource_type)
        check_val_type(json_body['resource_id'], int)


def check_resource_children(resource_dict, parent_resource_id, root_service_id):
    """
    Crawls through a resource-children tree to validate data field, types and corresponding values.
    :param resource_dict: top-level 'resources' dictionary possibly containing children resources.
    :param parent_resource_id: top-level resource/service id (int)
    :param root_service_id: top-level service id (int)
    :raise any invalid match on expected data field, type or value
    """
    assert isinstance(resource_dict, dict)

    for resource_id in resource_dict:
        check_val_type(resource_id, six.string_types)
        resource_int_id = int(resource_id)  # should by an 'int' string, no error raised
        resource_info = resource_dict[resource_id]
        check_val_is_in('root_service_id', resource_info)
        check_val_type(resource_info['root_service_id'], int)
        check_val_equal(resource_info['root_service_id'], root_service_id)
        check_val_is_in('resource_id', resource_info)
        check_val_type(resource_info['resource_id'], int)
        check_val_equal(resource_info['resource_id'], resource_int_id)
        check_val_is_in('parent_id', resource_info)
        check_val_type(resource_info['parent_id'], int)
        check_val_equal(resource_info['parent_id'], parent_resource_id)
        check_val_is_in('resource_name', resource_info)
        check_val_type(resource_info['resource_name'], six.string_types)
        check_val_is_in('permission_names', resource_info)
        check_val_type(resource_info['permission_names'], list)
        check_val_is_in('children', resource_info)
        check_resource_children(resource_info['children'], resource_int_id, root_service_id)


# Generic setup and validation methods across unittests
class TestSetup(object):
    @staticmethod
    def get_Version(test_class):
        resp = test_request(test_class.url, 'GET', '/version',
                            headers=test_class.json_headers, cookies=test_class.cookies)
        json_body = check_response_basic_info(resp, 200)
        return json_body['version']

    @staticmethod
    def check_UpStatus(test_class, method, path):
        """
        Verifies that the Magpie UI page at very least returned an Ok response with the displayed title.
        Validates that at the bare minimum, no underlying internal error occurred from the API or UI calls.
        """
        resp = test_request(test_class.url, method, path, cookies=test_class.cookies)
        check_val_equal(resp.status_code, 200)
        check_val_is_in('Content-Type', resp.headers)
        check_val_is_in('text/html', get_response_content_types_list(resp))
        check_val_is_in("Magpie Administration", resp.text)

    @staticmethod
    def get_AnyServiceOfTestServiceType(test_class):
        route = '/services/types/{}'.format(test_class.test_service_type)
        resp = test_request(test_class.url, 'GET', route, headers=test_class.json_headers, cookies=test_class.cookies)
        check_val_equal(resp.status_code, 200)
        json_body = resp.json()
        check_val_is_in('services', json_body)
        check_val_is_in(test_class.test_service_type, json_body['services'])
        check_val_not_equal(len(json_body['services'][test_class.test_service_type]), 0,
                            msg="Missing any required service of type: `{}`".format(test_class.test_service_type))
        services = json_body['services'][test_class.test_service_type]
        return services[services.keys()[0]]

    @staticmethod
    def create_TestServiceResource(test_class, data_override=None):
        route = '/services/{svc}/resources'.format(svc=test_class.test_service_name)
        data = {
            "resource_name": test_class.test_resource_name,
            "resource_type": test_class.test_resource_type,
        }
        if data_override:
            data.update(data_override)
        resp = test_request(test_class.url, 'POST', route,
                            headers=test_class.json_headers,
                            cookies=test_class.cookies, json=data)
        return check_response_basic_info(resp, 201)

    @staticmethod
    def get_ExistingTestServiceInfo(test_class):
        route = '/services/{svc}'.format(svc=test_class.test_service_name)
        resp = test_request(test_class.url, 'GET', route, headers=test_class.json_headers, cookies=test_class.cookies)
        return resp.json()[test_class.test_service_name]

    @staticmethod
    def get_ExistingTestServiceDirectResources(test_class):
        route = '/services/{svc}/resources'.format(svc=test_class.test_service_name)
        resp = test_request(test_class.url, 'GET', route, headers=test_class.json_headers, cookies=test_class.cookies)
        json_body = resp.json()
        resources = json_body[test_class.test_service_name]['resources']
        return [resources[res] for res in resources]

    @staticmethod
    def check_NonExistingTestResource(test_class):
        resources = TestSetup.get_ExistingTestServiceDirectResources(test_class)
        resources_names = [res['resource_name'] for res in resources]
        check_val_not_in(test_class.test_resource_name, resources_names)

    @staticmethod
    def delete_TestServiceResource(test_class):
        resources = TestSetup.get_ExistingTestServiceDirectResources(test_class)
        test_resource = filter(lambda r: r['resource_name'] == test_class.test_resource_name, resources)
        # delete as required, skip if non-existing
        if len(test_resource) > 0:
            resource_id = test_resource[0]['resource_id']
            route = '/services/{svc}/resources/{res_id}'.format(svc=test_class.test_service_name, res_id=resource_id)
            resp = test_request(test_class.url, 'DELETE', route,
                                headers=test_class.json_headers,
                                cookies=test_class.cookies)
            check_val_equal(resp.status_code, 200)
        TestSetup.check_NonExistingTestResource(test_class)

    @staticmethod
    def get_RegisteredServicesList(test_class):
        resp = test_request(test_class.url, 'GET', '/services',
                            headers=test_class.json_headers,
                            cookies=test_class.cookies)
        json_body = check_response_basic_info(resp, 200)

        # prepare a flat list of registered services
        services_list = list()
        for svc_type in json_body['services']:
            services_of_type = json_body['services'][svc_type]
            services_list.extend(services_of_type.values())
        return services_list

    @staticmethod
    def get_RegisteredUsersList(test_class):
        resp = test_request(test_class.url, 'GET', '/users',
                            headers=test_class.json_headers,
                            cookies=test_class.cookies)
        json_body = check_response_basic_info(resp, 200)
        return json_body['user_names']

    @staticmethod
    def check_NonExistingTestUser(test_class):
        users = TestSetup.get_RegisteredUsersList(test_class)
        check_val_not_in(test_class.test_user_name, users)

    @staticmethod
    def create_TestUser(test_class):
        data = {
            "user_name": test_class.test_user_name,
            "email": '{}@mail.com'.format(test_class.test_user_name),
            "password": test_class.test_user_name,
            "group_name": test_class.test_user_group,
        }
        resp = test_request(test_class.url, 'POST', '/users',
                            headers=test_class.json_headers,
                            cookies=test_class.cookies, json=data)
        return check_response_basic_info(resp, 201)

    @staticmethod
    def delete_TestUser(test_class):
        users = TestSetup.get_RegisteredUsersList(test_class)
        # delete as required, skip if non-existing
        if test_class.test_user_name in users:
            route = '/users/{usr}'.format(usr=test_class.test_user_name)
            resp = test_request(test_class.url, 'DELETE', route,
                                headers=test_class.json_headers,
                                cookies=test_class.cookies)
            check_val_equal(resp.status_code, 200)
        TestSetup.check_NonExistingTestUser(test_class)
