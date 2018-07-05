import os
import json
import pyramid
import requests
from webtest import TestApp
from webtest.response import TestResponse
from magpie import magpie, db
MAGPIE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


json_headers = [('Content-Type', 'application/json')]


def config_setup_from_ini(config_ini_file_path):
    settings = db.get_settings_from_config_ini(config_ini_file_path)
    config = pyramid.testing.setUp(settings=settings)
    return config


def get_test_magpie_app():
    # parse settings from ini file to pass them to the application
    magpie_ini = '{}/magpie/magpie.ini'.format(MAGPIE_DIR)
    config = config_setup_from_ini(magpie_ini)
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


def check_or_try_login_user(app_or_url, username=None, password=None):
    """
    Verifies that the required user is already logged in (or none is if username=None), or tries to login him otherwise.

    :param app_or_url: `webtest.TestApp` instance of the test application or remote server URL to call with `requests`
    :param username: name of the user to login or None otherwise
    :param password: password to use for login if the user was not already logged in
    :return: headers and cookies of the user session or (None, None)
    :raise: Exception on any login/logout failure as required by the caller's specifications (username/password)
    """

    if isinstance(app_or_url, TestApp):
        resp = app_or_url.get('/session', headers=json_headers)
        body = resp.json
    else:
        resp = requests.get('{}/session'.format(app_or_url), headers=dict(json_headers))
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
            resp = app_or_url.post_json('/signin', data, headers=json_headers)
        else:
            resp = requests.post('{}/signin'.format(app_or_url), json=data, headers=dict(json_headers))

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


def all_equal(iterable_test, iterable_ref, any_order=False):
    if not (hasattr(iterable_test, '__iterable__') and hasattr(iterable_ref, '__iterable__')):
        return False
    if len(iterable_test) != len(iterable_ref):
        return False
    if any_order:
        return all([it in iterable_ref for it in iterable_test])
    return all(it == ir for it, ir in zip(iterable_test, iterable_ref))
