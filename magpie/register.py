import os
import time
import yaml
import subprocess
import requests
import logging
from distutils.dir_util import mkpath

LOGGER = logging.getLogger(__name__)

LOGIN_ATTEMPT = 10              # max attempts for login
LOGIN_TIMEOUT = 10              # delay (s) between each login attempt
LOGIN_TMP_DIR = "/tmp"          # where to temporarily store login cookies
CREATE_SERVICE_INTERVAL = 2     # delay (s) between creations to allow server to respond/process
GETCAPABILITIES_INTERVAL = 10   # delay (s) between 'GetCapabilities' Phoenix calls to validate service registration
GETCAPABILITIES_ATTEMPTS = 12   # max attempts for 'GetCapabilities' validations

# controls
SERVICES_MAGPIE  = 'MAGPIE'
SERVICES_PHOENIX = 'PHOENIX'
SERVICES_PHOENIX_ALLOWED = ['WPS']


def print_log(msg):
    print(msg)
    LOGGER.debug(msg)


def bool2str(value):
    return 'true' if value in ['on', 'true', 'True', True] else 'false'


def str2bool(value):
    return True if value in ['on', 'true', 'True', True] else False


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
    attempt = 0
    while True:
        err, http = request_curl(login_url, cookie_jar=cookies_file, form_params=data_str, msg=message)
        if not err and http == 200:
            break
        time.sleep(LOGIN_TIMEOUT)
        attempt += 1
        if attempt >= LOGIN_ATTEMPT:
            raise Exception('Cannot log in to {0}'.format(login_url))


def request_curl(url, cookie_jar=None, cookies=None, form_params=None, msg='Response'):
    # arg -k allows to ignore insecure SSL errors, ie: access 'https' page not configured for it
    ###curl_cmd = 'curl -k -L -s -o /dev/null -w "{msg_out} : %{{http_code}}\\n" {params} {url}'
    ###curl_cmd = curl_cmd.format(msg_out=msg, params=params, url=url)
    msg_sep = msg + ": "
    params = ['curl', '-k', '-L', '-s', '-o', '/dev/null', '-w', msg_sep + '%{http_code}']
    if cookie_jar is not None and cookies is not None:
        raise ValueError("Cookies and Cookie_Jar cannot be both set simultaneously")
    if cookie_jar is not None:
        params.extend(['--cookie-jar', cookie_jar])  # save cookies
    if cookies is not None:
        params.extend(['--cookie', cookies])         # use cookies
    if form_params is not None:
        params.extend(['--data', form_params])
    params.extend([url])
    curl_out = subprocess.Popen(params, stdout=subprocess.PIPE)
    curl_msg = curl_out.communicate()[0]
    curl_err = curl_out.returncode
    http_code = int(curl_msg.split(msg_sep)[1])
    print_log("[{url}] {response}".format(response=curl_msg, url=url))
    return curl_err, http_code


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
    error = True
    try:
        phoenix_login(phoenix_cookies)
        phoenix_url = get_phoenix_url()
        remove_services_url = phoenix_url + '/clear_services'
        error, http_code = request_curl(remove_services_url, cookies=phoenix_cookies, msg='Phoenix remove services')
    except Exception as e:
        print_log("Exception during phoenix remove services: [" + repr(e) + "]")
    finally:
        if os.path.isfile(phoenix_cookies):
            os.remove(phoenix_cookies)
    return not error


def phoenix_register_services(services_dict, allowed_service_types=None):
    phoenix_cookies = os.path.join(LOGIN_TMP_DIR, 'login_cookie_phoenix')
    success = False
    statuses = dict()
    try:
        allowed_service_types = SERVICES_PHOENIX_ALLOWED if allowed_service_types is None else allowed_service_types
        allowed_service_types = [svc.upper() for svc in allowed_service_types]
        phoenix_login(phoenix_cookies)

        # Filter specific services to push
        filtered_services_dict = {}
        for svc in services_dict:
            if str(services_dict[svc].get('type')).upper() in allowed_service_types:
                filtered_services_dict[svc] = services_dict[svc]
                filtered_services_dict[svc]['type'] = filtered_services_dict[svc]['type'].upper()

        # Register services
        phoenix_url = get_phoenix_url()
        register_service_url = phoenix_url + '/services/register'
        success, statuses = register_services(register_service_url, filtered_services_dict,
                                              phoenix_cookies, 'Phoenix register service', SERVICES_PHOENIX)
    except Exception as e:
        print_log("Exception during phoenix register services: [" + repr(e) + "]")
    finally:
        if os.path.isfile(phoenix_cookies):
            os.remove(phoenix_cookies)
    return success, statuses


def get_phoenix_url():
    try:
        hostname = os.getenv('HOSTNAME')
        phoenix_port = os.environ.get('PHOENIX_PORT')
        if hostname is None:
            raise ValueError("Environment variable was None", 'HOSTNAME')
        if phoenix_port is None:
            raise ValueError("Environment variable was None", 'PHOENIX_PORT')
        if phoenix_port != '':
            phoenix_port = ':{0}'.format(phoenix_port)
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")
    return 'https://{0}{1}'.format(hostname, phoenix_port)


def get_magpie_url():
    try:
        hostname = os.getenv('HOSTNAME')
        magpie_port = os.environ.get('MAGPIE_PORT')
        if hostname is None:
            raise ValueError("Environment variable was None", 'HOSTNAME')
        if magpie_port is None:
            raise ValueError("Environment variable was None", 'MAGPIE_PORT')
        if magpie_port != '':
            magpie_port = ':{0}'.format(magpie_port)
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")
    return 'http://{0}{1}'.format(hostname, magpie_port)


def register_services(register_service_url, services_dict, cookies,
                      message='Register response', where=SERVICES_MAGPIE):
    success = True
    statuses = dict()
    if where == SERVICES_MAGPIE:
        svc_url_tag = 'service_url'
    elif where == SERVICES_PHOENIX:
        svc_url_tag = 'url'
    else:
        raise ValueError("Unknown location for service registration", where)
    for service_name in services_dict:
        cfg = services_dict[service_name]
        cfg['url'] = os.path.expandvars(cfg.get('url'))
        cfg['public'] = bool2str(cfg.get('public'))
        cfg['c4i'] = bool2str(cfg.get('c4i'))
        params = 'service_name={name}&'         \
                 '{svc_url}={cfg[url]}&'        \
                 'service_title={cfg[title]}&'  \
                 'public={cfg[public]}&'        \
                 'c4i={cfg[c4i]}&'              \
                 'service_type={cfg[type]}&'    \
                 'register=register'            \
                 .format(name=service_name, cfg=cfg, svc_url=svc_url_tag)
        service_msg = '{msg} ({svc})'.format(msg=message, svc=service_name)
        error, http_code = request_curl(register_service_url, cookies=cookies, form_params=params, msg=service_msg)
        statuses[service_name] = http_code
        success = success and not error and ((where == SERVICES_PHOENIX and http_code == 200) or
                                             (where == SERVICES_MAGPIE and http_code == 201))
        time.sleep(CREATE_SERVICE_INTERVAL)
    return success, statuses


def sync_services_phoenix(services_object_list):
    services_dict = {}
    for svc in services_object_list:
        services_dict[svc.resource_name] = {'url': svc.url, 'title': svc.resource_name,
                                            'type': svc.type, 'c4i': False, 'public': True}
    phoenix_remove_services()
    phoenix_register_services(services_dict)


def magpie_add_register_services_perms(services, statuses, cookies):
    magpie_url = get_magpie_url()
    for service_name, status in zip(services, statuses):
        svc_available_perms_url = '{magpie}/services/{svc}/permissions' \
                                  .format(magpie=magpie_url, svc=service_name)
        resp_available_perms = requests.get(svc_available_perms_url)
        available_perms = resp_available_perms.json().get('permission_names', [])
        # only applicable to services supporting 'GetCapabilities' request
        if resp_available_perms.status_code and 'getcapabilities' in available_perms:

            # add 'getcapabilities' permission if available for service just created
            if status == 201:
                svc_anonym_add_perms_url = '{magpie}/groups/{grp}/services/{svc}/permissions' \
                                           .format(magpie=magpie_url, grp='anonymous', svc=service_name)
                requests.post(svc_anonym_add_perms_url, data={'permission_name': 'getcapabilities'})

            # check service response so Phoenix doesn't refuse registration
            # try with both the 'direct' URL and the 'GetCapabilities' URL
            attempt = 0
            service_info = '{magpie}/services/{svc}'.format(magpie=magpie_url, svc=service_name)
            service_url = requests.get(service_info).json().get(service_name).get('service_url')
            svc_getcap_url = '{svc_url}/wps?service=WPS&version=1.0.0&request=GetCapabilities' \
                             .format(svc_url=service_url)
            while True:
                service_msg_direct = "Service response ({svc})".format(svc=service_name)
                service_msg_getcap = "Service response ({svc}, GetCapabilities)".format(svc=service_name)
                err, http = request_curl(service_url, cookies=cookies, msg=service_msg_direct)
                if not err and http == 200:
                    break
                err, http = request_curl(svc_getcap_url, cookies=cookies, msg=service_msg_getcap)
                if not err and http == 200:
                    break
                print_log("[{url}] Bad response from service '{svc}' retrying after {sec}s..."
                          .format(svc=service_name, url=service_url, sec=GETCAPABILITIES_INTERVAL))
                time.sleep(GETCAPABILITIES_INTERVAL)
                attempt += 1
                if attempt >= GETCAPABILITIES_ATTEMPTS:
                    msg = "[{url}] No response from service '{svc}' after {tries} attempts. Skipping..." \
                          .format(svc=service_name, url=service_url, tries=attempt)
                    print_log(msg)
                    break


def magpie_update_services_conflict(conflict_services, services_dict):
    magpie_url = get_magpie_url()
    for svc_name in conflict_services:
        svc_url_new = services_dict[svc_name]['url']
        svc_url_db = '{magpie}/services/{svc}'.format(magpie=magpie_url, svc=svc_name)
        svc_info = requests.get(svc_url_db).json().get(svc_name)
        svc_url_old = svc_info['service_url']
        svc_info['service_url'] = svc_url_new
        res_svc_put = requests.put(svc_url_db, data=svc_info)
        print_log("[{url_old}] => [{url_new}] Service URL update ({svc}): {resp}" \
                  .format(svc=svc_name, url_old=svc_url_old, url_new=svc_url_new, resp=res_svc_put.status_code))


def magpie_register_services_from_config(service_config_file_path, push_to_phoenix=False):
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
    magpie_register_services(services, push_to_phoenix, admin_usr, admin_pwd, 'ziggurat', force_update=True)


def magpie_register_services(services_dict, push_to_phoenix, user, password, provider, force_update=False):
    magpie_url = get_magpie_url()
    magpie_cookies = os.path.join(LOGIN_TMP_DIR, 'login_cookie_magpie')
    success = False
    try:
        # Need to login first as admin
        login_url = magpie_url + '/signin'
        login_data = {'user_name': user, 'password': password, 'provider_name': provider}
        login_loop(login_url, magpie_cookies, login_data, 'Magpie login response')

        # Register services
        # Magpie will not overwrite existing services by default, 409 Conflict instead of 201 Created
        register_service_url = magpie_url + '/services'
        success, statuses = register_services(register_service_url, services_dict, magpie_cookies,
                                              'Magpie register service', SERVICES_MAGPIE)
        # Service URL update if conflicting and requested
        if force_update and not success:
            conflict_services = [svc_name for svc_name, http_code in statuses.items() if http_code == 409]
            magpie_update_services_conflict(conflict_services, services_dict)

        # Add 'GetCapabilities' permissions on newly created services to allow 'ping' from Phoenix
        # Phoenix doesn't register the service if it cannot be checked with this request
        magpie_add_register_services_perms(services_dict, statuses, magpie_cookies)

        # Push updated services to Phoenix
        if push_to_phoenix:
            phoenix_remove_services()
            phoenix_register_services(services_dict)

    except Exception as e:
        print_log("Exception during magpie register services: [" + repr(e) + "]")
    finally:
        if os.path.isfile(magpie_cookies):
            os.remove(magpie_cookies)
    return success
