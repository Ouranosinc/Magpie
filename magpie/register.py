from magpie.api.api_rest_schemas import (
    SigninAPI,
    SignoutAPI,
    ServicesAPI,
    ServiceAPI,
    ServiceResourcesAPI,
    GroupResourcePermissionsAPI,
    UserResourcePermissionsAPI,
)
from magpie.common import make_dirs, print_log, raise_log, bool2str
from magpie.constants import get_constant
from magpie.definitions.ziggurat_definitions import UserService, UserResourcePermissionService
from magpie.definitions.sqlalchemy_definitions import Session
from magpie.permissions import permissions_supported
from magpie.services import service_type_dict
from magpie import models
from typing import AnyStr, Dict, List, Optional, Tuple, Union, TYPE_CHECKING
import os
import six
import time
import yaml
import subprocess
import requests
import transaction
# noinspection PyUnresolvedReferences
import logging
import logging.config   # find config in 'logging.ini'
LOGGER = logging.getLogger(__name__)

LOGIN_ATTEMPT = 10              # max attempts for login
LOGIN_TIMEOUT = 10              # delay (s) between each login attempt
LOGIN_TMP_DIR = "/tmp"          # where to temporarily store login cookies
CREATE_SERVICE_INTERVAL = 2     # delay (s) between creations to allow server to respond/process
GETCAPABILITIES_INTERVAL = 10   # delay (s) between 'GetCapabilities' Phoenix calls to validate service registration
GETCAPABILITIES_ATTEMPTS = 12   # max attempts for 'GetCapabilities' validations

# controls
SERVICES_MAGPIE = 'MAGPIE'
SERVICES_PHOENIX = 'PHOENIX'
SERVICES_PHOENIX_ALLOWED = ['wps']

if TYPE_CHECKING:
    ConfigItem = Dict[AnyStr, AnyStr]
    ConfigList = List[ConfigItem]
    ConfigDict = Dict[AnyStr, Union[ConfigItem, ConfigList]]


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
    # type: (AnyStr, Optional[AnyStr], Optional[AnyStr], Optional[AnyStr], Optional[AnyStr]) -> Tuple[int, int]
    """Executes a request using cURL.

    :returns: tuple of the returned system command code and the response http code
    """

    # arg -k allows to ignore insecure SSL errors, ie: access 'https' page not configured for it
    #   curl_cmd = 'curl -k -L -s -o /dev/null -w "{msg_out} : %{{http_code}}\\n" {params} {url}'
    #   curl_cmd = curl_cmd.format(msg_out=msg, params=params, url=url)
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
    curl_msg = curl_out.communicate()[0]    # type: AnyStr
    curl_err = curl_out.returncode          # type: int
    http_code = int(curl_msg.split(msg_sep)[1])
    print_log("[{url}] {response}".format(response=curl_msg, url=url))
    return curl_err, http_code


def phoenix_update_services(services_dict):
    if not phoenix_remove_services():
        print_log("Could not remove services, aborting register sync services to Phoenix")
        return False
    if not phoenix_register_services(services_dict):
        print_log("Failed services registration from Magpie to Phoenix\n" +
                  "[warning: services could have been removed but could not be re-added]")
        return False
    return True


def phoenix_login(cookies):
    phoenix_pwd = get_constant('PHOENIX_PASSWORD')
    phoenix_url = get_phoenix_url()
    login_url = phoenix_url + '/account/login/phoenix'
    login_data = {'password': phoenix_pwd, 'submit': 'submit'}
    login_loop(login_url, cookies, login_data, 'Phoenix login response')
    return phoenix_login_check(cookies)


def phoenix_login_check(cookies):
    """
    Since Phoenix always return 200, even on invalid login, 'hack' check unauthorized access.
    :param cookies: temporary cookies file storage used for login with `phoenix_login`.
    :return: status indicating if login access was granted with defined credentials.
    """
    no_access_error = "<ExceptionText>Unauthorized: Services failed permission check</ExceptionText>"
    svc_url = get_phoenix_url() + '/services'
    curl_process = subprocess.Popen(['curl', '-s', '--cookie', cookies, svc_url], stdout=subprocess.PIPE)
    curl_http_resp = curl_process.communicate()
    has_access = no_access_error not in curl_http_resp[0]
    return has_access


def phoenix_remove_services():
    # type: (...) -> bool
    """Removes the Phoenix services using temporary cookies retrieved from login with defined `PHOENIX` constants.

    :returns: success status of the procedure.
    """
    phoenix_cookies = os.path.join(LOGIN_TMP_DIR, 'login_cookie_phoenix')
    error = 0
    try:
        if not phoenix_login(phoenix_cookies):
            print_log("Login unsuccessful from post-login check, aborting...")
            return False
        phoenix_url = get_phoenix_url()
        remove_services_url = phoenix_url + '/clear_services'
        error, http_code = request_curl(remove_services_url, cookies=phoenix_cookies, msg='Phoenix remove services')
    except Exception as e:
        print_log("Exception during phoenix remove services: [" + repr(e) + "]")
    finally:
        if os.path.isfile(phoenix_cookies):
            os.remove(phoenix_cookies)
    return error == 0


def phoenix_register_services(services_dict, allowed_service_types=None):
    phoenix_cookies = os.path.join(LOGIN_TMP_DIR, 'login_cookie_phoenix')
    success = False
    statuses = dict()
    try:
        allowed_service_types = SERVICES_PHOENIX_ALLOWED if allowed_service_types is None else allowed_service_types
        allowed_service_types = [svc.upper() for svc in allowed_service_types]
        if not phoenix_login(phoenix_cookies):
            print_log("Login unsuccessful from post-login check, aborting...")
            return False

        # Filter specific services to push
        filtered_services_dict = {}
        for svc in services_dict:
            if str(services_dict[svc].get('type')).upper() in allowed_service_types:
                filtered_services_dict[svc] = services_dict[svc]
                filtered_services_dict[svc]['type'] = filtered_services_dict[svc]['type'].upper()

        # Register services
        success, statuses = register_services(SERVICES_PHOENIX, filtered_services_dict,
                                              phoenix_cookies, 'Phoenix register service')
    except Exception as e:
        print_log("Exception during phoenix register services: [" + repr(e) + "]")
    finally:
        if os.path.isfile(phoenix_cookies):
            os.remove(phoenix_cookies)
    return success, statuses


def get_phoenix_url():
    hostname = get_constant('HOSTNAME')
    phoenix_port = get_constant('PHOENIX_PORT', raise_not_set=False)
    return 'https://{0}{1}'.format(hostname, ':{}'.format(phoenix_port) if phoenix_port else '')


def get_magpie_url():
    hostname = get_constant('HOSTNAME')
    magpie_port = get_constant('MAGPIE_PORT', raise_not_set=False)
    return 'http://{0}{1}'.format(hostname, ':{}'.format(magpie_port) if magpie_port else '')


def get_twitcher_protected_service_url(magpie_service_name, hostname=None):
    twitcher_proxy_url = get_constant('TWITCHER_PROTECTED_URL', raise_not_set=False)
    if not twitcher_proxy_url:
        twitcher_proxy = get_constant('TWITCHER_PROTECTED_PATH', raise_not_set=False)
        if not twitcher_proxy.endswith('/'):
            twitcher_proxy = twitcher_proxy + '/'
        if not twitcher_proxy.startswith('/'):
            twitcher_proxy = '/' + twitcher_proxy
        if not twitcher_proxy.startswith('/twitcher'):
            twitcher_proxy = '/twitcher' + twitcher_proxy
        hostname = hostname or get_constant('HOSTNAME')
        twitcher_proxy_url = "https://{0}{1}".format(hostname, twitcher_proxy)
    twitcher_proxy_url = twitcher_proxy_url.rstrip('/')
    return "{0}/{1}".format(twitcher_proxy_url, magpie_service_name)


def register_services(where,                        # type: Optional[AnyStr]
                      services_dict,                # type: Dict[AnyStr, Dict[AnyStr, AnyStr]]
                      cookies,                      # type: AnyStr
                      message='Register response',  # type: AnyStr
                      ):                            # type: (...) -> Tuple[bool, Dict[AnyStr, int]]
    """
    Registers services on desired location using provided configurations and access cookies.

    :returns: tuple of overall success and individual http response of each service registration.
    """
    success = True
    svc_url = None
    statuses = dict()
    register_service_url = None
    if where == SERVICES_MAGPIE:
        svc_url_tag = 'service_url'
        get_magpie_url() + ServicesAPI.path
    elif where == SERVICES_PHOENIX:
        svc_url_tag = 'url'
        register_service_url = get_phoenix_url() + '/services/register'
    else:
        raise ValueError("Unknown location for service registration", where)
    for service_name in services_dict:
        cfg = services_dict[service_name]
        cfg['public'] = bool2str(cfg.get('public'))
        cfg['c4i'] = bool2str(cfg.get('c4i'))
        cfg['url'] = os.path.expandvars(cfg.get('url'))
        if where == SERVICES_MAGPIE:
            svc_url = cfg['url']
        elif where == SERVICES_PHOENIX:
            svc_url = get_twitcher_protected_service_url(service_name)
        params = 'service_name={name}&'         \
                 '{svc_url_tag}={svc_url}&'     \
                 'service_title={cfg[title]}&'  \
                 'public={cfg[public]}&'        \
                 'c4i={cfg[c4i]}&'              \
                 'service_type={cfg[type]}&'    \
                 'register=register'            \
                 .format(name=service_name, cfg=cfg, svc_url_tag=svc_url_tag, svc_url=svc_url)
        service_msg = '{msg} ({svc}) [{url}]'.format(msg=message, svc=service_name, url=svc_url)
        error, http_code = request_curl(register_service_url, cookies=cookies, form_params=params, msg=service_msg)
        statuses[service_name] = http_code
        success = success and not error and ((where == SERVICES_PHOENIX and http_code == 200) or
                                             (where == SERVICES_MAGPIE and http_code == 201))
        time.sleep(CREATE_SERVICE_INTERVAL)
    return success, statuses


def sync_services_phoenix(services_object_dict, services_as_dicts=False):
    """
    Syncs Magpie services by pushing updates to Phoenix.
    Services must be one of types specified in SERVICES_PHOENIX_ALLOWED.

    :param services_object_dict: dictionary of {svc-name: models.Service} objects containing each service's information
    :param services_as_dicts: alternatively specify `services_object_dict` as dict of {svc-name: {service-info}}
    where {service-info} = {'public_url': <url>, 'service_name': <name>, 'service_type': <type>}
    """
    services_dict = {}
    for svc in services_object_dict:
        if services_as_dicts:
            svc_dict = services_object_dict[svc]
            services_dict[svc] = {'url': svc_dict['public_url'], 'title': svc_dict['service_name'],
                                  'type': svc_dict['service_type'], 'c4i': False, 'public': True}
        else:
            services_dict[svc.resource_name] = {'url': svc.url, 'title': svc.resource_name,
                                                'type': svc.type, 'c4i': False, 'public': True}

    return phoenix_update_services(services_dict)


def magpie_add_register_services_perms(services, statuses, curl_cookies, request_cookies, disable_getcapabilities):
    magpie_url = get_magpie_url()
    login_usr = get_constant('MAGPIE_ANONYMOUS_USER')

    for service_name in services:
        svc_available_perms_url = '{magpie}/services/{svc}/permissions' \
                                  .format(magpie=magpie_url, svc=service_name)
        resp_available_perms = requests.get(svc_available_perms_url, cookies=request_cookies)
        if resp_available_perms.status_code == 401:
            raise_log("Invalid credentials, cannot update service permissions", exception=ValueError)

        available_perms = resp_available_perms.json().get('permission_names', [])
        # only applicable to services supporting 'GetCapabilities' request
        if resp_available_perms.status_code and 'getcapabilities' in available_perms:

            # enforce 'getcapabilities' permission if available for service just updated (200) or created (201)
            # update 'getcapabilities' permission when the service existed and it allowed
            if (not disable_getcapabilities and statuses[service_name] == 409) \
            or statuses[service_name] == 200 or statuses[service_name] == 201:
                svc_anonym_add_perms_url = '{magpie}/users/{usr}/services/{svc}/permissions' \
                                           .format(magpie=magpie_url, usr=login_usr, svc=service_name)
                svc_anonym_perm_data = {'permission_name': 'getcapabilities'}
                requests.post(svc_anonym_add_perms_url, data=svc_anonym_perm_data, cookies=request_cookies)

            # check service response so Phoenix doesn't refuse registration
            # try with both the 'direct' URL and the 'GetCapabilities' URL
            attempt = 0
            service_info_url = '{magpie}/services/{svc}'.format(magpie=magpie_url, svc=service_name)
            service_info_resp = requests.get(service_info_url, cookies=request_cookies)
            service_url = service_info_resp.json().get(service_name).get('service_url')
            svc_getcap_url = '{svc_url}/wps?service=WPS&version=1.0.0&request=GetCapabilities' \
                             .format(svc_url=service_url)
            while True:
                service_msg_direct = "Service response ({svc})".format(svc=service_name)
                service_msg_getcap = "Service response ({svc}, GetCapabilities)".format(svc=service_name)
                err, http = request_curl(service_url, cookies=curl_cookies, msg=service_msg_direct)
                if not err and http == 200:
                    break
                err, http = request_curl(svc_getcap_url, cookies=curl_cookies, msg=service_msg_getcap)
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


def magpie_update_services_conflict(conflict_services, services_dict, request_cookies):
    # type: (List[AnyStr], ConfigDict, Dict[AnyStr, AnyStr]) -> Dict[AnyStr, int]
    """Resolve conflicting services by name during registration by updating them only if pointing to different URL."""
    magpie_url = get_magpie_url()
    statuses = dict()
    for svc_name in conflict_services:
        statuses[svc_name] = 409
        svc_url_new = services_dict[svc_name]['url']
        svc_url_db = '{magpie}/services/{svc}'.format(magpie=magpie_url, svc=svc_name)
        svc_info = requests.get(svc_url_db, cookies=request_cookies).json().get(svc_name)
        svc_url_old = svc_info['service_url']
        if svc_url_old != svc_url_new:
            svc_info['service_url'] = svc_url_new
            res_svc_put = requests.put(svc_url_db, data=svc_info, cookies=request_cookies)
            statuses[svc_name] = res_svc_put.status_code
            print_log("[{url_old}] => [{url_new}] Service URL update ({svc}): {resp}"
                      .format(svc=svc_name, url_old=svc_url_old, url_new=svc_url_new, resp=res_svc_put.status_code))
    return statuses


def magpie_register_services(services_dict, push_to_phoenix, username, password, provider,
                             force_update=False, disable_getcapabilities=False):
    # type: (ConfigDict, bool, AnyStr, AnyStr, AnyStr, Optional[bool], Optional[bool]) -> bool
    """
    Registers magpie services using the provided services configuration.

    :param services_dict: services configuration definition.
    :param push_to_phoenix: push registered Magpie services to Phoenix for synced configurations.
    :param username: login username to use to obtain permissions for services registration.
    :param password: login password to use to obtain permissions for services registration.
    :param provider: login provider to use to obtain permissions for services registration.
    :param force_update: override existing services matched by name
    :param disable_getcapabilities: do not execute 'GetCapabilities' validation for applicable services.
    :return: successful operation status
    """
    magpie_url = get_magpie_url()
    curl_cookies = os.path.join(LOGIN_TMP_DIR, 'login_cookie_magpie')
    session = requests.Session()
    success = False
    try:
        # Need to login first as admin
        login_url = magpie_url + SigninAPI.path
        login_data = {'user_name': username, 'password': password, 'provider_name': provider}
        login_loop(login_url, curl_cookies, login_data, 'Magpie login response')
        login_resp = session.post(login_url, data=login_data)
        if login_resp.status_code != 200:
            raise_log('Failed login with specified credentials')
        request_cookies = login_resp.cookies

        # Register services
        # Magpie will not overwrite existing services by default, 409 Conflict instead of 201 Created
        success, statuses_register = register_services(SERVICES_MAGPIE, services_dict,
                                                       curl_cookies, 'Magpie register service')
        # Service URL update if conflicting and requested
        if force_update and not success:
            conflict_services = [svc_name for svc_name, http_code in statuses_register.items() if http_code == 409]
            statuses_update = magpie_update_services_conflict(conflict_services, services_dict, request_cookies)
            statuses_register.update(statuses_update)  # update previous statuses with new ones

        # Add 'GetCapabilities' permissions on newly created services to allow 'ping' from Phoenix
        # Phoenix doesn't register the service if it cannot be checked with this request
        magpie_add_register_services_perms(services_dict, statuses_register,
                                           curl_cookies, request_cookies, disable_getcapabilities)
        session.get(magpie_url + SignoutAPI.path)

        # Push updated services to Phoenix
        if push_to_phoenix:
            success = phoenix_update_services(services_dict)

    except Exception as e:
        print_log("Exception during magpie register services: [" + repr(e) + "]")
    finally:
        session.cookies.clear()
        if os.path.isfile(curl_cookies):
            os.remove(curl_cookies)
    return success


def magpie_register_services_with_db_session(services_dict, db_session, push_to_phoenix=False,
                                             force_update=False, update_getcapabilities_permissions=False):
    existing_services_names = [n[0] for n in db_session.query(models.Service.resource_name)]
    magpie_anonymous_user = get_constant('MAGPIE_ANONYMOUS_USER')
    anonymous_user = UserService.by_user_name(magpie_anonymous_user, db_session=db_session)

    for svc_name, svc_values in services_dict.items():
        svc_new_url = os.path.expandvars(svc_values['url'])
        svc_type = svc_values['type']

        svc_sync_type = svc_values.get('sync_type')
        if force_update and svc_name in existing_services_names:
            svc = models.Service.by_service_name(svc_name, db_session=db_session)
            if svc.url == svc_new_url:
                print_log("Service URL already properly set [{url}] ({svc})".format(url=svc.url, svc=svc_name))
            else:
                print_log("Service URL update [{url_old}] => [{url_new}] ({svc})"
                          .format(url_old=svc.url, url_new=svc_new_url, svc=svc_name))
                svc.url = svc_new_url
            svc.sync_type = svc_sync_type
        elif not force_update and svc_name in existing_services_names:
            print_log("Skipping service [{svc}] (conflict)" .format(svc=svc_name))
        else:
            print_log("Adding service [{svc}]".format(svc=svc_name))
            # noinspection PyArgumentList
            svc = models.Service(resource_name=svc_name,
                                 resource_type=models.Service.resource_type_name,
                                 url=svc_new_url,
                                 type=svc_type,
                                 sync_type=svc_sync_type)
            db_session.add(svc)

        if update_getcapabilities_permissions and anonymous_user is None:
            print_log("Cannot update 'getcapabilities' permission of non existing anonymous user", level=logging.WARN)
        elif update_getcapabilities_permissions and 'getcapabilities' in service_type_dict[svc_type].permission_names:
            svc = db_session.query(models.Service.resource_id).filter_by(resource_name=svc_name).first()
            svc_perm_getcapabilities = UserResourcePermissionService.by_resource_user_and_perm(
                user_id=anonymous_user.id, perm_name='getcapabilities',
                resource_id=svc.resource_id, db_session=db_session
            )
            if svc_perm_getcapabilities is None:
                print_log("Adding 'getcapabilities' permission to anonymous user")
                # noinspection PyArgumentList
                svc_perm_getcapabilities = models.UserResourcePermission(
                    user_id=anonymous_user.id, perm_name='getcapabilities', resource_id=svc.resource_id
                )
                db_session.add(svc_perm_getcapabilities)

    transaction.commit()
    db_session.close()

    if push_to_phoenix:
        return phoenix_update_services(services_dict)
    return True


def _load_config(path_or_dict, section):
    # type: (Union[AnyStr, ConfigDict], AnyStr) -> ConfigDict
    """Loads a file path or dictionary as YAML/JSON configuration."""
    try:
        if isinstance(path_or_dict, six.string_types):
            cfg = yaml.load(open(path_or_dict, 'r'))
        else:
            cfg = path_or_dict
        return cfg[section]
    except KeyError as ex:
        raise_log("Config file section [{!s}] not found.".format(section), exception=type(ex))
    except Exception as ex:
        raise_log("Invalid config file [{!r}]".format(ex), exception=type(ex))


def magpie_register_services_from_config(service_config_file_path, push_to_phoenix=False,
                                         force_update=False, disable_getcapabilities=False, db_session=None):
    # type: (AnyStr, Optional[bool], Optional[bool], Optional[bool], Optional[Session]) -> None
    """
    Registers Magpie services from a `providers.cfg` file.
    Uses the provided DB session to directly update service definitions, or uses API request routes as admin.
    Optionally pushes updates to Phoenix.
    """
    services = _load_config(service_config_file_path, 'providers')
    if not services:
        LOGGER.warning("Services configuration are empty.")
        return

    # register services using API POSTs
    if db_session is None:
        admin_usr = get_constant('MAGPIE_ADMIN_USER')
        admin_pwd = get_constant('MAGPIE_ADMIN_PASSWORD')
        magpie_register_services(services, push_to_phoenix, admin_usr, admin_pwd, 'ziggurat',
                                 force_update=force_update, disable_getcapabilities=disable_getcapabilities)

    # register services directly to db using session
    else:
        magpie_register_services_with_db_session(services, db_session,
                                                 push_to_phoenix=push_to_phoenix, force_update=force_update,
                                                 update_getcapabilities_permissions=not disable_getcapabilities)


def warn_permission(msg, _i, trail="skipping...", detail=None, level=logging.WARN):
    if detail:
        trail = "{}\nDetail: [{!r}]".format(trail, detail)
    LOGGER.log(level, "{!s} [permission #{}], {}".format(msg, _i, trail))


def parse_resource_path(permission_config_entry, entry_index, service_info, cookies):
    # type: (ConfigItem, int, ConfigItem, Dict[AnyStr, AnyStr]) -> Tuple[Union[int, None], bool]
    """
    Parses the `resource` field of a permission config entry and retrieves the final resource id.
    Creates missing resources as necessary if they can be automatically resolved.

    :returns: tuple of found id (if any, `None` otherwise), and success status of the parsing operation (error)
    """
    resource = None
    resource_path = permission_config_entry.get('resource', '')
    if resource_path.startswith('/'):
        resource_path = resource_path[1:]
    if resource_path.endswith('/'):
        resource_path = resource_path[:-1]
    if resource_path:
        try:
            svc_name = service_info['service_name']
            svc_type = service_info['service_type']
            res_path = get_magpie_url() + ServiceResourcesAPI.path.format(service_name=svc_name)
            res_dict = requests.get(res_path, cookies=cookies).json()[svc_name]['resources']
            parent = None
            for res in resource_path.split('/'):
                if len(res_dict):
                    # resource is specified by id/name
                    res_id = filter(lambda r: res in [r, res_dict[r]["resource_name"]], res_dict)
                    if res_id:
                        res_dict = res_dict[res_id[0]]['children']  # update for upcoming sub-resource iteration
                        parent = int(res[0])
                        continue
                # missing resource, attempt creation
                type_count = len(service_type_dict[svc_type].resource_types)
                if type_count != 1:
                    warn_permission("Cannot automatically generate resources", entry_index,
                                    detail="Service [{}] of type [{}] allows {} sub-resource types"
                                           .format(svc_name, svc_type, type_count))
                    raise Exception("Missing resource to apply permission.")  # fail fast
                res_type = service_type_dict[svc_type].resource_types[0]
                body = {'resource_name': res, 'resource_type': res_type, 'parent_id': parent}
                resp = requests.post(res_path, json=body, cookies=cookies)
                if resp.status_code != 201:
                    resp.raise_for_status()
                parent = resp.json()['resource']['resource_id']
            resource = parent
            if not resource:
                raise Exception("Could not extract child resource from resource path.")
        except Exception as ex:
            warn_permission("Failed resources parsing.", entry_index, detail=ex)
            return None, False
    return resource, True


def magpie_register_permissions_from_config(permissions_config):
    # type: (Union[AnyStr, ConfigDict]) -> None
    """
    Applies permissions specified in configuration.

    .. seealso::
        `magpie/permissions.cfg` for specific parameter or operational details.
    """

    permissions = _load_config(permissions_config, 'permissions')
    if not permissions:
        LOGGER.warning("Permissions configuration are empty.")
        return

    magpie_url = get_magpie_url()
    admin_usr = get_constant('MAGPIE_ADMIN_USER')
    admin_pwd = get_constant('MAGPIE_ADMIN_PASSWORD')
    body = {'user_name': admin_usr, 'password': admin_pwd}
    resp = requests.post(magpie_url + SigninAPI.path, json=body)
    if resp.status_code != 200:
        raise_log("Cannot register Magpie permissions without proper credentials.")
    admin_cookies = resp.cookies

    logging.info("Found {} permissions to update.".format(len(permissions)))
    for i, perm in enumerate(permissions):
        # parameter validation
        if not isinstance(perm, dict) or not all(f in perm for f in ['permission', 'service']):
            warn_permission("Invalid permission format for [{!s}]".format(perm), i)
            continue
        if perm['permission'] not in permissions_supported:
            warn_permission("Unknown permission [{!s}]".format(perm['permission']), i)
            continue
        usr_name = perm.get('user')
        grp_name = perm.get('group')
        if not any([usr_name, grp_name]):
            warn_permission("Missing required user and/or group field.", i)
            continue
        if 'action' not in perm:
            warn_permission("Unspecified action", i, trail="using default (create)...")
            perm['action'] = 'create'
        if perm['action'] not in ['create', 'remove']:
            warn_permission("Unknown action [{!s}]".format(perm['action']), i)
            continue
        svc_name = perm['service']
        svc_path = magpie_url + ServiceAPI.path.format(service_name=svc_name)
        svc_resp = requests.get(svc_path, cookies=admin_cookies)
        if svc_resp.status_code != 200:
            warn_permission("Unknown service [{!s}]".format(svc_name), i)
            continue
        service_info = svc_resp.json()[svc_name]

        # apply permission config
        resource, found = parse_resource_path(perm, i, service_info, admin_cookies)
        if not found:
            continue
        if not resource:
            resource = service_info['resource_id']
        perm_paths = list()
        if usr_name:
            perm_paths.append(UserResourcePermissionsAPI.path.replace('{user_name}', usr_name))
        if grp_name:
            perm_paths.append(GroupResourcePermissionsAPI.path.replace('{group_name}', grp_name))
        for path in perm_paths:
            create_perm = perm['action'] == 'create'
            if create_perm:
                action_func = requests.post
                action_path = '{url}{path}'.format(url=magpie_url, path=path)
                action_body = {'permission_name': perm['permission']}
            else:
                action_func = requests.delete
                action_path = '{url}{path}/{perm_name}'.format(url=magpie_url, path=path, perm_name=perm['permission'])
                action_body = {}
            action_path = action_path.format(resource_id=resource)
            action_resp = action_func(action_path, json=action_body, cookies=admin_cookies)
            action_code = action_resp.status_code
            if create_perm:
                if action_code == 201:
                    warn_permission("Permission successfully created.", i, level=logging.INFO)
                elif action_code == 409:
                    warn_permission("Permission already exists: {!s}".format(perm), i, level=logging.INFO)
                else:
                    warn_permission("Unknown response for 'create' permission [{}]: {!s}"
                                    .format(action_code, perm), i, level=logging.ERROR)
            else:
                if action_code == 200:
                    warn_permission("Permission successfully removed.", i, level=logging.INFO)
                elif action_code == 404:
                    warn_permission("Permission successfully removed.", i, level=logging.INFO)
                else:
                    warn_permission("Unknown response for 'remove' permission [{}]: {!s}"
                                    .format(action_code, perm), i, level=logging.ERROR)
    logging.info("Done processing permissions.")
