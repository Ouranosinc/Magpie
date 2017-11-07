import os
import time
import yaml
import sys


def register_providers():
    admin_name = os.getenv('ADMIN_USER')
    admin_password = os.getenv('ADMIN_PASSWORD')

    try:
        providers_cfg = yaml.load(open(sys.argv[1], 'r'))
        providers = providers_cfg['providers']
    except Exception as e:
        raise Exception("Bad provider file + [" + repr(e) + "]")

    hostname = os.getenv('HOSTNAME')
    magpie_port = os.getenv('MAGPIE_PORT')

    curl_cmd = 'curl -L -s -o /dev/null -w "{msg_out} : %{{http_code}}\\n" {params} {url}'

    # Need to login first as admin
    login_url = 'http://{0}:{1}/signin'.format(hostname, magpie_port)
    cookie_fn = '/tmp/login_cookie'

    attempt = 0
    while attempt < 10:
        params = '--cookie-jar {0} --data "user_name={1}&password={2}&provider_name={3}"' \
                 .format(cookie_fn, admin_name, admin_password, 'ziggurat')
        if os.system(curl_cmd.format(msg_out='Login response', params=params, url=login_url)) == 0:
            break
        time.sleep(6)
        attempt += 1
    if attempt == 10:
        raise Exception('Cannot log in to {0}'.format(login_url))

    register_service_url = 'http://{0}:{1}/services'.format(hostname, magpie_port)

    for provider in providers:
        cfg = providers[provider]
        url = os.path.expandvars(cfg['url'])
        public = 'true' if providers[provider]['public'] else 'false'
        params = '--cookie {cookie} '           \
                 '--data "'                     \
                 'service_name={name}&'         \
                 'service_url={url}&'           \
                 'service_title={cfg[title]}&'  \
                 'public={public}&'             \
                 'c4i={cfg[c4i]}&'              \
                 'service_type={cfg[type]}&'    \
                 'register=register"'           \
                 .format(cookie=cookie_fn, name=provider, url=url, public=public, cfg=cfg)

        os.system(curl_cmd.format(msg_out='Register response',
                                  params=params, url=register_service_url))

    os.remove(cookie_fn)


if __name__ == "__main__":
    register_providers()
