import os
import time
import yaml
import sys

LOGIN_ATTEMPT = 10
LOGIN_TIMEOUT = 10


def login_loop(login_url, cookies, admin_name, admin_password, extra_data=''):
    extra_data = '&' + str(extra_data) if extra_data is not None else ''
    params = '--cookie-jar {0} --data "user_name={1}&password={2}{3}"' \
        .format(cookies, admin_name, admin_password, extra_data)
    attempt = 0
    while True:
        if request_curl(login_url, params, 'Login response'):
            break
        time.sleep(LOGIN_TIMEOUT)
        attempt += 1
        if attempt >= LOGIN_ATTEMPT:
            raise Exception('Cannot log in to {0}'.format(login_url))


def request_curl(url, params, msg='Response'):
    curl_cmd = 'curl -L -s -o /dev/null -w "{msg_out} : %{{http_code}}\\n" {params} {url}'
    return os.system(curl_cmd.format(msg_out=msg, params=params, url=url)) == 0


def phoenix_login(cookies):
    try:
        phoenix_usr = os.getenv('PHOENIX_USER')
        phoenix_pwd = os.getenv('PHOENIX_PASSWORD')
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")
    phoenix_url = get_phoenix_url()
    login_url = phoenix_url + '/account/login/phoenix'
    login_loop(login_url, cookies, phoenix_usr, phoenix_pwd, 'submit=submit')


def phoenix_remove_services():
    phoenix_cookies = '/tmp/login_cookie_phoenix'
    phoenix_login(phoenix_cookies)

    phoenix_url = get_phoenix_url()
    remove_services_url = phoenix_url + '/clear_services'
    success = request_curl(remove_services_url, '', 'Remove response')

    os.remove(phoenix_cookies)
    return success


def phoenix_register_services(services_dict):
    phoenix_cookies = '/tmp/login_cookie_phoenix'
    phoenix_login(phoenix_cookies)

    # Register WPS services
    phoenix_url = get_phoenix_url()
    register_service_url = phoenix_url + '/services/register'
    wps_services_dict = [wps_service for wps_service in services_dict
                         if str(wps_service.get('type')).lower() == 'wps']
    success = register_services(register_service_url, wps_services_dict, phoenix_cookies)

    os.remove(phoenix_cookies)
    return success


def get_phoenix_url():
    try:
        hostname = os.getenv('HOSTNAME')
        phoenix_port = os.getenv('PHOENIX_PORT')
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")
    return 'https://{0}:{1}'.format(hostname, phoenix_port)


def get_magpie_url():
    try:
        hostname = os.getenv('HOSTNAME')
        magpie_port = os.getenv('MAGPIE_PORT')
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")
    return 'http://{0}:{1}'.format(hostname, magpie_port)


def register_services(register_service_url, services_dict, cookies):
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
        success = success and request_curl(register_service_url, params, 'Register response')
    return success


def magpie_register_services():
    try:
        admin_name = os.getenv('ADMIN_USER')
        admin_password = os.getenv('ADMIN_PASSWORD')
    except Exception as e:
        raise Exception("Missing environment values [" + repr(e) + "]")

    try:
        services_cfg = yaml.load(open(sys.argv[1], 'r'))
        services = services_cfg['services']
    except Exception as e:
        raise Exception("Bad service file + [" + repr(e) + "]")
    magpie_url = get_magpie_url()

    # Need to login first as admin
    login_url = magpie_url + '/signin'
    cookie_fn = '/tmp/login_cookie_magpie'
    login_loop(login_url, cookie_fn, admin_name, admin_password, 'provider_name=ziggurat')

    # Register services
    register_service_url = magpie_url + '/services'
    success = register_services(register_service_url, services, cookie_fn)

    os.remove(cookie_fn)
    return success
