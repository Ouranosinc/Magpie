import os
import time
import yaml
from distutils.dir_util import mkpath

LOGIN_ATTEMPT = 10              # max attempts for login
LOGIN_TIMEOUT = 10              # delay (s) between each login attempt
LOGIN_TMP_DIR = "/tmp"          # where to temporarily store login cookies
CREATE_SERVICE_INTERVAL = 2     # delay (s) between creations to allow server to respond/process


# alternative to 'makedirs' with 'exists_ok' parameter only available for python>3.5
def make_dirs(path):
    dir_path = os.path.dirname(path)
    if not os.path.isfile(path) or not os.path.isdir(dir_path):
        for subdir in mkpath(dir_path):
            if not os.path.isdir(subdir):
                os.mkdir(subdir)


def login_loop(login_url, cookies_file, data=None, message='Login response'):
    make_dirs(cookies_file)
    data_str = ''
    if data is not None and type(data) is dict:
        for key in data:
            data_str = data_str + '&' + str(key) + '=' + str(data[key])
    if type(data) is str:
        data_str = data
    params = '--cookie-jar {0} --data "{1}"'.format(cookies_file, data_str)
    attempt = 0
    while True:
        if request_curl(login_url, params, message):
            break
        time.sleep(LOGIN_TIMEOUT)
        attempt += 1
        if attempt >= LOGIN_ATTEMPT:
            raise Exception('Cannot log in to {0}'.format(login_url))


def request_curl(url, params, msg='Response'):
    # arg -k allows to ignore insecure SSL errors, ie: access 'https' page not configured for it
    curl_cmd = 'curl -k -L -s -o /dev/null -w "{msg_out} : %{{http_code}}\\n" {params} {url}'
    return os.system(curl_cmd.format(msg_out=msg, params=params, url=url)) == 0


def phoenix_login(cookies):
    try:
        phoenix_pwd = os.getenv('PHOENIX_PASSWORD')
        if phoenix_pwd is None:
            raise ValueError("Environment variable was None", 'PHOENIX_PASSWORD')
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")
    phoenix_url = get_phoenix_url()
    login_url = phoenix_url + '/account/login/phoenix'
    login_data = {'password': phoenix_pwd, 'submit': 'submit'}
    login_loop(login_url, cookies, login_data, 'Phoenix login response')


def phoenix_remove_services():
    phoenix_cookies = os.path.join(LOGIN_TMP_DIR, 'login_cookie_phoenix')
    phoenix_login(phoenix_cookies)

    phoenix_url = get_phoenix_url()
    remove_services_url = phoenix_url + '/clear_services'
    success = request_curl(remove_services_url, '', 'Phoenix remove services')

    os.remove(phoenix_cookies)
    return success


def phoenix_register_services(services_dict, allowed_service_types=None):
    allowed_service_types = ['wps'] if allowed_service_types is None else allowed_service_types
    phoenix_cookies = os.path.join(LOGIN_TMP_DIR, 'login_cookie_phoenix')
    phoenix_login(phoenix_cookies)

    # Register WPS services
    phoenix_url = get_phoenix_url()
    register_service_url = phoenix_url + '/services/register'
    filtered_services_dict = {}
    for svc in services_dict:
        if str(services_dict[svc].get('type')).lower() in allowed_service_types:
            filtered_services_dict[svc] = services_dict[svc]
    success = register_services(register_service_url, filtered_services_dict,
                                phoenix_cookies, 'Phoenix register service')

    os.remove(phoenix_cookies)
    return success


def get_phoenix_url():
    try:
        hostname = os.getenv('HOSTNAME')
        phoenix_port = os.getenv('PHOENIX_PORT')
        if hostname is None:
            raise ValueError("Environment variable was None", 'HOSTNAME')
        if phoenix_port is None:
            raise ValueError("Environment variable was None", 'PHOENIX_PORT')
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")
    return 'https://{0}:{1}'.format(hostname, phoenix_port)


def get_magpie_url():
    try:
        hostname = os.getenv('HOSTNAME')
        magpie_port = os.getenv('MAGPIE_PORT')
        if hostname is None:
            raise ValueError("Environment variable was None", 'HOSTNAME')
        if magpie_port is None:
            raise ValueError("Environment variable was None", 'MAGPIE_PORT')
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")
    return 'http://{0}:{1}'.format(hostname, magpie_port)


def register_services(register_service_url, services_dict, cookies, message='Register response'):
    success = True
    for service in services_dict:
        cfg = services_dict[service]
        url = os.path.expandvars(cfg['url'])
        public = 'true' if cfg['public'] else 'false'
        params = '--cookie {cookie} '           \
                 '--data "'                     \
                 'service_name={name}&'         \
                 'service_url={url}&'           \
                 'service_title={cfg[title]}&'  \
                 'public={public}&'             \
                 'c4i={cfg[c4i]}&'              \
                 'service_type={cfg[type]}&'    \
                 'register=register"'           \
                 .format(cookie=cookies, name=service, url=url, public=public, cfg=cfg)
        success = success and request_curl(register_service_url, params, message)
        time.sleep(CREATE_SERVICE_INTERVAL)
    return success


def magpie_register_services(service_config_file_path, push_to_phoenix=False):
    try:
        admin_usr = os.getenv('ADMIN_USER')
        admin_pwd = os.getenv('ADMIN_PASSWORD')
        if admin_usr is None:
            raise ValueError("Environment variable was None", 'ADMIN_USER')
        if admin_pwd is None:
            raise ValueError("Environment variable was None", 'ADMIN_PASSWORD')
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")

    try:
        services_cfg = yaml.load(open(service_config_file_path, 'r'))
        services = services_cfg['providers']
    except Exception as e:
        raise Exception("Bad service file + [" + repr(e) + "]")
    magpie_url = get_magpie_url()

    # Need to login first as admin
    login_url = magpie_url + '/signin'
    magpie_cookies = os.path.join(LOGIN_TMP_DIR, 'login_cookie_magpie')
    login_data = {'user_name': admin_usr, 'password': admin_pwd, 'provider_name': 'ziggurat'}
    login_loop(login_url, magpie_cookies, login_data, 'Magpie login response')

    # Register services
    # Magpie will not overwrite existing services by default, 409 Conflict instead of 201 Created
    register_service_url = magpie_url + '/services'
    success = register_services(register_service_url, services, magpie_cookies, 'Magpie register service')

    # Push updated services to Phoenix
    if push_to_phoenix:
        phoenix_remove_services()
        phoenix_register_services(services)

    os.remove(magpie_cookies)
    return success
