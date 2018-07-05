import six
import pyramid
import requests
from webtest import TestApp
from webtest.response import TestResponse
from magpie import magpie, db
from magpie import *


def config_setup_from_ini(config_ini_file_path):
    settings = db.get_settings_from_config_ini(config_ini_file_path)
    config = pyramid.testing.setUp(settings=settings)
    return config


def get_test_magpie_app():
    # parse settings from ini file to pass them to the application
    config = config_setup_from_ini(MAGPIE_INI_FILE_PATH)
    # required redefinition because root models' location is not the same from within this test file
    config.add_settings({'ziggurat_foundations.model_locations.User': 'magpie.models:User',
                         'ziggurat_foundations.model_locations.user': 'magpie.models:User'})
    config.include('ziggurat_foundations.ext.pyramid.sign_in')
    # remove API which cause duplicate view errors (?) TODO: figure out why it does so, because it shouldn't
    config.registry.settings['magpie.api_generation_disabled'] = True
    # scan dependencies
    config.include('magpie')
    config.scan('magpie')
    # create the test application
    app = TestApp(magpie.main({}, **config.registry.settings))
    return app


def test_request(app_or_url, method, path, timeout=5, allow_redirects=True, **kwargs):
    """
    Calls the request using either a `webtest.TestApp` instance or a `requests` instance from a string URL.
    :param app_or_url: `webtest.TestApp` instance of the test application or remote server URL to call with `requests`
    :param method: request method (GET, POST, PUT, DELETE)
    :param path: test path starting at base path
    :return: response of the request
    """
    method = method.upper()
    if isinstance(app_or_url, TestApp):
        if method == 'GET':
            return app_or_url.get(path, **kwargs)
        elif method == 'POST':
            return app_or_url.post_json(path, **kwargs)
        elif method == 'PUT':
            return app_or_url.put_json(path, **kwargs)
        elif method == 'DELETE':
            return app_or_url.delete_json(path, **kwargs)
    else:
        url = '{url}{path}'.format(url=app_or_url, path=path)
        return requests.request(method, url, timeout=timeout, allow_redirects=allow_redirects, **kwargs)


def check_or_try_login_user(app_or_url, username=None, password=None, headers=None):
    """
    Verifies that the required user is already logged in (or none is if username=None), or tries to login him otherwise.

    :param app_or_url: `webtest.TestApp` instance of the test application or remote server URL to call with `requests`
    :param username: name of the user to login or None otherwise
    :param password: password to use for login if the user was not already logged in
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


def check_response_basic_info(response, expected_code=200):
    if isinstance(response, TestResponse):
        json_body = response.json
    else:
        json_body = response.json()
    assert response.status_code == expected_code
    assert response.headers['Content-Type'] == 'application/json'
    assert json_body['type'] == 'application/json'
    assert json_body['code'] == expected_code
    assert json_body['detail'] != ''


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
        assert isinstance(resource_id, six.string_types)
        resource_int_id = int(resource_id)  # should by an 'int' string, no error raised
        resource_info = resource_dict[resource_id]
        assert 'root_service_id' in resource_info
        assert isinstance(resource_info['root_service_id'], int)
        assert resource_info['root_service_id'] == root_service_id
        assert 'resource_id' in resource_info
        assert isinstance(resource_info['resource_id'], int)
        assert resource_info['resource_id'] == resource_int_id
        assert 'parent_id' in resource_info
        assert isinstance(resource_info['parent_id'], int)
        assert resource_info['parent_id'] == parent_resource_id
        assert 'resource_name' in resource_info
        assert isinstance(resource_info['resource_name'], six.string_types)
        assert 'permission_names' in resource_info
        assert isinstance(resource_info['permission_names'], list)
        assert 'children' in resource_info

        check_resource_children(resource_info['children'], resource_int_id, root_service_id)


def all_equal(iterable_test, iterable_ref, any_order=False):
    if not (hasattr(iterable_test, '__iter__') and hasattr(iterable_ref, '__iter__')):
        return False
    if len(iterable_test) != len(iterable_ref):
        return False
    if any_order:
        return all([it in iterable_ref for it in iterable_test])
    return all(it == ir for it, ir in zip(iterable_test, iterable_ref))
