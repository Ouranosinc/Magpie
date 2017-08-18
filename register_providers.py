import os
import time
import yaml
import sys



admin_name = os.getenv('ADMIN_USER')
admin_password = os.getenv('ADMIN_PASSWORD')

try:
  providers_cfg = yaml.load(file(sys.argv[1], 'r'))
  providers = providers_cfg['providers']
except:
  raise Exception('Bad provider files')

hostname = os.getenv('HOSTNAME')
magpie_port = os.getenv('MAGPIE_PORT')

curl_cmd = 'curl -L -s -o /dev/null -w "{msg_out} : %{{http_code}}\\n" {params} {url}' 

# Need to login first as admin
login_url = 'http://{0}:{1}/signin'.format(hostname, magpie_port)
cookie_fn = '/tmp/login_cookie'

attempt = 0
while attempt < 10:
  if os.system(curl_cmd.format(msg_out='Login response', 
                                 params=('--cookie-jar {0} '
                                         '--data "user_name={1}&password={2}&provider_name={3}"').format(cookie_fn, admin_name, admin_password, 'ziggurat'), 
                                 url=login_url)) == 0: 
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
    params= ('--cookie {cookie} '
             '--data "'
             'service_name={name}&'
             'service_url={url}&'
             'service_title={cfg[title]}&'
             'public={public}&'
             'c4i={cfg[c4i]}&'
             'service_type={cfg[type]}&'
             'register=register"').format(cookie=cookie_fn,
                                          name=provider,
                                          url=url,
                                          public=public,
                                          cfg=cfg)

    os.system(curl_cmd.format(msg_out='Register response',
                              params=params,
                              url=register_service_url))

os.remove(cookie_fn)


#get_version_url = 'http://{0}:{1}/version'.format(hostname, magpie_port)

#os.system(curl_cmd.format(msg_out='Version response', 
#                                    params=('--cookie {cookie} ').format(cookie=cookie_fn),
#                                    url=get_version_url))
# for each provider
  # get the cookie and set it in the header
  # send a Post request to create service







'''


hostname = os.environ['HOSTNAME']
curl_cmd = 'curl -c -s -o /dev/null -w "{msg_out} : %{{http_code}}\\n" {params} {url}'
providers_cfg = yaml.load(file('./providers.cfg', 'r'))
admin_pw = providers_cfg['admin_pw']
providers = providers_cfg['providers']
login_url = 'https://{0}:8443/account/login/phoenix'.format(hostname)
cookie_fn = '/tmp/login_cookie'

# Allow some time for Phoenix to start (if we are called in the docker startup sequence)
attempt = 0
while attempt < 10:
    if os.system(curl_cmd.format(msg_out='Login response',
                                 params=('--cookie-jar {0} '
                                         '--data "password={1}&submit=submit"').format(cookie_fn, admin_pw),
                                 url=login_url)) == 0:
        break
    time.sleep(6)
    attempt += 1
if attempt == 10:
    raise Exception('Cannot log in to {0}'.format(login_url))    

for provider in providers:
    cfg = providers[provider]
    url = os.path.expandvars(cfg['url'])
    public = 'true' if providers[provider]['public'] else 'false'
    params= ('--cookie {cookie} '
             '--data "'
             'service_name={name}&'
             'url={url}&'
             'service_title={cfg[title]}&'
             'public={public}&'
             'c4i={cfg[c4i]}&'
             'service_type=WPS&'
             'register=register"').format(cookie=cookie_fn,
                                          name=provider,
                                          url=url,
                                          public=public,
                                          cfg=cfg)

    os.system(curl_cmd.format(msg_out='Register response',
                              params=params,
                              url='https://{0}:8443/services/register'.format(hostname)))
os.remove(cookie_fn)

'''