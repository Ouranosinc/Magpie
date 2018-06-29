import os
import json
import pyramid
from webtest import TestApp
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
    config.add_settings({'ziggurat_foundations.model_locations.User': 'magpie.models:User'})
    # scan dependencies
    config.include('magpie')
    config.scan('magpie')
    # create the test application
    app = TestApp(magpie.main({}, **config.registry.settings))
    return app


def check_or_try_login_user(app, username=None, password=None):
    """
    Verifies that the required user is already logged in (or none is if username=None), or tries to login him otherwise.

    :param app: instance of the test application
    :param username: name of the user to login or None otherwise
    :param password: password to use for login if the user was not already logged in
    :return: cookie headers of the user session or None
    :raise: Exception on any login/logout failure as required by the caller's specifications (username/password)
    """
    resp = app.get('/session', headers=json_headers)
    if resp.status_int != 200:
        raise Exception('cannot retrieve logged in user information')
    auth = resp.json.get('authenticated', False)
    user = resp.json.get('user_name', '')
    if auth is False and username is None:
        return None
    if auth is False and username is not None:
        data = {'user_name': username, 'password': password, 'provider_name': 'ziggurat'}
        resp = app.post_json('/signin', data, headers=json_headers)
        if resp.status_int == 200:
            return resp.json['headers']
        return None
    if auth is True and username != user:
        raise Exception("invalid user")
