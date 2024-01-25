import logging
import os
import random
import string
import subprocess  # nosec
import time
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

import requests
import six
import transaction
import yaml
from pyramid.httpexceptions import HTTPException
from sqlalchemy.orm.session import Session
from ziggurat_foundations.models.services.group import GroupService
from ziggurat_foundations.models.services.resource import ResourceService
from ziggurat_foundations.models.services.user import UserService
from ziggurat_foundations.models.services.user_resource_permission import UserResourcePermissionService

from magpie import models
from magpie.api.schemas import (
    GroupResourcePermissionsAPI,
    GroupsAPI,
    ServiceAPI,
    ServiceResourcesAPI,
    ServicesAPI,
    SigninAPI,
    SignoutAPI,
    UserResourcePermissionsAPI,
    UsersAPI
)
from magpie.config import validate_services_config
from magpie.constants import get_constant
from magpie.permissions import Permission, PermissionSet
from magpie.services import SERVICE_TYPE_DICT, ServiceWPS
from magpie.utils import (
    bool2str,
    get_admin_cookies,
    get_json,
    get_logger,
    get_magpie_url,
    get_phoenix_url,
    get_twitcher_protected_service_url,
    islambda,
    print_log,
    raise_log
)

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

    from magpie.typedefs import (
        JSON,
        AnyCookiesType,
        AnyResolvedSettings,
        AnyResponseType,
        CombinedConfig,
        CookiesOrSessionType,
        GroupsConfig,
        GroupsSettings,
        MultiConfigs,
        PermissionConfigItem,
        PermissionsConfig,
        ServicesConfig,
        ServicesSettings,
        Str,
        UsersConfig,
        UsersSettings
    )


LOGGER = get_logger(__name__)

LOGIN_ATTEMPT = 5               # max attempts for login
LOGIN_TIMEOUT = 2               # delay (s) between each login attempt
CREATE_SERVICE_INTERVAL = 2     # delay (s) between creations to allow server to respond/process
GETCAPABILITIES_INTERVAL = 10   # delay (s) between 'GetCapabilities' Phoenix calls to validate service registration
GETCAPABILITIES_ATTEMPTS = 12   # max attempts for 'GetCapabilities' validations

# controls
SERVICES_MAGPIE = "MAGPIE"
SERVICES_PHOENIX = "PHOENIX"
SERVICES_PHOENIX_ALLOWED = [ServiceWPS.service_type]


class RegistrationError(RuntimeError):
    """
    Generic error during registration operation.
    """


class RegistrationValueError(RegistrationError, ValueError):
    """
    Registration error caused by an invalid value precondition.
    """


class RegistrationLoginError(RegistrationError):
    """
    Registration error caused by a failure to complete required login operation.
    """


class RegistrationConfigurationError(RegistrationValueError):
    """
    Registration error caused by an invalid configuration entry or definition.
    """


def _login_loop(login_url, cookies_file, data=None, message="Login response"):
    cookies_dir = os.path.dirname(cookies_file)
    if not os.path.isdir(cookies_dir):
        os.makedirs(cookies_dir)  # don't use "exist_ok" for backward compatibility (Python<3.5)
    data_str = ""
    if data is not None and isinstance(data, dict):
        for key in data:
            data_str = data_str + "&" + str(key) + "=" + str(data[key])
    if isinstance(data, six.string_types):
        data_str = data
    attempt = 0
    while True:
        err, http = _request_curl(login_url, cookie_jar=cookies_file, form_params=data_str, msg=message)
        if not err and http == 200:
            break
        attempt += 1
        LOGGER.warning("Login failed, retrying in %ss (%s/%s)", LOGIN_TIMEOUT, attempt, LOGIN_ATTEMPT)
        time.sleep(LOGIN_TIMEOUT)
        if attempt >= LOGIN_ATTEMPT:
            raise RegistrationLoginError("Cannot log in to {0}".format(login_url))


def _request_curl(url, cookie_jar=None, cookies=None, form_params=None, msg="Response"):
    # type: (Str, Optional[Str], Optional[Str], Optional[Str], Optional[Str]) -> Tuple[int, int]
    """
    Executes a request using cURL.

    :returns: tuple of the returned system command code and the response http code
    """

    # arg -k allows to ignore insecure SSL errors, ie: access 'https' page not configured for it
    #   curl_cmd = 'curl -k -L -s -o /dev/null -w "{msg_out} : %{{http_code}}\\n" {params} {url}'
    #   curl_cmd = curl_cmd.format(msg_out=msg, params=params, url=url)
    msg_sep = msg + ": "
    params = ["curl", "-k", "-L", "-s", "-o", "/dev/null", "-w", msg_sep + "%{http_code}"]
    if cookie_jar is not None and cookies is not None:
        raise RegistrationValueError("CookiesType and Cookie_Jar cannot be both set simultaneously")
    if cookie_jar is not None:
        params.extend(["--cookie-jar", cookie_jar])  # save cookies
    if cookies is not None:
        params.extend(["--cookie", cookies])         # use cookies
    if form_params is not None:
        params.extend(["--data", form_params])
    params.extend([url])
    with subprocess.Popen(params, stdout=subprocess.PIPE) as curl_proc:  # nosec
        curl_msg = curl_proc.communicate()[0]    # type: Str
        curl_err = curl_proc.returncode          # type: int
    http_code = int(six.ensure_text(curl_msg).split(msg_sep)[1])
    print_log("[{url}] {response}".format(response=curl_msg, url=url), logger=LOGGER)
    return curl_err, http_code


def _phoenix_update_services(services_dict):
    # type: (JSON) -> bool
    if not _phoenix_remove_services():
        print_log("Could not remove services, aborting register sync services to Phoenix", logger=LOGGER)
        return False
    success, _ = _phoenix_register_services(services_dict)
    if not success:
        print_log("Failed services registration from Magpie to Phoenix\n"
                  "[warning: services could have been removed but could not be re-added]", logger=LOGGER)
        return False
    return True


def _phoenix_login(cookies_file):
    # type: (Str) -> bool
    """
    Performs Phoenix login using provided cookies.
    """
    phoenix_pwd = get_constant("PHOENIX_PASSWORD")
    phoenix_url = get_phoenix_url()
    login_url = phoenix_url + "/account/login/phoenix"
    login_data = {"password": phoenix_pwd, "submit": "submit"}
    _login_loop(login_url, cookies_file, login_data, "Phoenix login response")
    return _phoenix_login_check(cookies_file)


def _phoenix_login_check(cookies):
    # type: (Str) -> bool
    """
    Since Phoenix always return 200, even on invalid login, 'hack' check unauthorized access.

    :param cookies: temporary cookies file storage used for login with :func:`_phoenix_login`.
    :return: status indicating if login access was granted with defined credentials.
    """
    no_access_error = "<ExceptionText>Unauthorized: Services failed permission check</ExceptionText>"
    svc_url = get_phoenix_url() + "/services"
    command = ["curl", "-s", "--cookie", cookies, svc_url]
    with subprocess.Popen(command, stdout=subprocess.PIPE) as curl_process:  # nosec
        curl_http_resp = curl_process.communicate()  # nosec
    has_access = no_access_error not in curl_http_resp[0]
    return has_access


def _phoenix_remove_services():
    # type: () -> bool
    """
    Removes the Phoenix services using temporary cookies retrieved from login with defined `PHOENIX` constants.

    :returns: success status of the procedure.
    """
    error = 0
    try:
        with NamedTemporaryFile() as phoenix_cookies_file:
            if not _phoenix_login(phoenix_cookies_file.name):
                print_log("Login unsuccessful from post-login check, aborting...", logger=LOGGER)
                return False
            phoenix_url = get_phoenix_url()
            remove_services_url = phoenix_url + "/clear_services"
            error, _ = _request_curl(remove_services_url, cookies=phoenix_cookies_file.name,
                                     msg="Phoenix remove services")
    except Exception as exc:
        print_log("Exception during phoenix remove services: [{!r}]".format(exc), logger=LOGGER, level=logging.ERROR)
    return error == 0


def _phoenix_register_services(services_dict, allowed_service_types=None):
    # type: (Dict[Str, Dict[Str, Any]], Optional[List[Str]]) -> Tuple[bool, Dict[Str, int]]

    success = False
    statuses = {}
    try:
        with NamedTemporaryFile() as phoenix_cookies_file:
            allowed_service_types = SERVICES_PHOENIX_ALLOWED if allowed_service_types is None else allowed_service_types
            allowed_service_types = [svc.upper() for svc in allowed_service_types]
            if not _phoenix_login(phoenix_cookies_file.name):
                print_log("Login unsuccessful from post-login check, aborting...", logger=LOGGER, level=logging.WARN)
                return False, {}

            # Filter specific services to push
            filtered_services_dict = {}
            for svc in services_dict:
                if str(services_dict[svc].get("type")).upper() in allowed_service_types:
                    filtered_services_dict[svc] = services_dict[svc]
                    filtered_services_dict[svc]["type"] = filtered_services_dict[svc]["type"].upper()

            # Register services
            success, statuses = _register_services(SERVICES_PHOENIX, filtered_services_dict,
                                                   phoenix_cookies_file.name, "Phoenix register service")
    except Exception as exc:
        print_log("Exception during phoenix register services: [{!r}]".format(exc), logger=LOGGER, level=logging.ERROR)
    return success, statuses


def _register_services(where,                           # type: Optional[Str]
                       services_dict,                   # type: Dict[Str, Dict[Str, Str]]
                       cookies,                         # type: Str
                       message="Register response",     # type: Optional[Str]
                       ):                               # type: (...) -> Tuple[bool, Dict[Str, int]]
    """
    Registers services on desired location using provided configurations and access cookies.

    :returns: tuple of overall success and individual http response of each service registration.
    """
    success = True
    svc_url = None
    statuses = {}
    if where == SERVICES_MAGPIE:
        svc_url_tag = "service_url"
        register_service_url = get_magpie_url() + ServicesAPI.path
    elif where == SERVICES_PHOENIX:
        svc_url_tag = "url"
        register_service_url = get_phoenix_url() + "/services/register"
    else:
        raise RegistrationValueError("Unknown location for service registration", where)
    for service_name in services_dict:
        cfg = services_dict[service_name]
        cfg["public"] = bool2str(cfg.get("public"))
        cfg["c4i"] = bool2str(cfg.get("c4i"))
        cfg["url"] = cfg.get("url")
        if where == SERVICES_MAGPIE:
            svc_url = cfg["url"]
        elif where == SERVICES_PHOENIX:
            svc_url = get_twitcher_protected_service_url(service_name)
        params = "service_name={name}&"         \
                 "{svc_url_tag}={svc_url}&"     \
                 "service_title={cfg[title]}&"  \
                 "public={cfg[public]}&"        \
                 "c4i={cfg[c4i]}&"              \
                 "service_type={cfg[type]}&"    \
                 "register=register"            \
                 .format(name=service_name, cfg=cfg, svc_url_tag=svc_url_tag, svc_url=svc_url)
        service_msg = "{msg} ({svc}) [{url}]".format(msg=message, svc=service_name, url=svc_url)
        error, http_code = _request_curl(register_service_url, cookies=cookies, form_params=params, msg=service_msg)
        statuses[service_name] = http_code
        success = success and not error and ((where == SERVICES_PHOENIX and http_code == 200) or
                                             (where == SERVICES_MAGPIE and http_code == 201))
        time.sleep(CREATE_SERVICE_INTERVAL)
    return success, statuses


def sync_services_phoenix(services, services_as_dicts=False):
    # type: (Union[Iterable[models.Service], JSON], bool) -> bool
    """
    Syncs Magpie services by pushing updates to Phoenix.

    Services must be one of types specified in :py:data:`magpie.register.SERVICES_PHOENIX_ALLOWED`.

    :param services:
        An iterable of :class:`models.Service` by default, or a dictionary of ``{svc-name: {<service-info>}}`` JSON
        objects containing each service's information if :paramref:`services_ad_dicts` is ``True``.

        where ``<service-info>`` is defined as::

            {"public_url": <url>, "service_name": <name>, "service_type": <type>}

    :param services_as_dicts: indicate if services must be parsed as JSON definitions.
    """
    services_dict = {}
    for svc in services:
        if services_as_dicts:
            svc_dict = services[svc]  # type: JSON
            services_dict[svc] = {"url": svc_dict["public_url"], "title": svc_dict["service_name"],
                                  "type": svc_dict["service_type"], "c4i": False, "public": True}
        else:
            services_dict[svc.resource_name] = {"url": svc.url, "title": svc.resource_name,
                                                "type": svc.type, "c4i": False, "public": True}

    return _phoenix_update_services(services_dict)


def _magpie_add_register_services_perms(services, statuses, curl_cookies, request_cookies, disable_getcapabilities):
    # type: (ServicesSettings, Dict[Str, int], str, AnyCookiesType, bool) -> None
    magpie_url = get_magpie_url()
    anon_group = get_constant("MAGPIE_ANONYMOUS_GROUP")

    for service_name in services:
        svc_available_perms_url = "{magpie}/services/{svc}/permissions" \
                                  .format(magpie=magpie_url, svc=service_name)
        resp_available_perms = requests.get(svc_available_perms_url, cookies=request_cookies, timeout=5)
        if resp_available_perms.status_code == 401:
            raise_log("Invalid credentials, cannot update service permissions",
                      exception=RegistrationLoginError, logger=LOGGER)

        available_perms = get_json(resp_available_perms).get("permission_names", [])
        # only applicable to services supporting "GetCapabilities" request
        if resp_available_perms.status_code and Permission.GET_CAPABILITIES.value in available_perms:

            # enforce 'getcapabilities' permission if available for service just updated (200) or created (201)
            # update 'getcapabilities' permission when the service existed and it allowed
            if ((not disable_getcapabilities and statuses[service_name] == 409)
                    or statuses[service_name] == 200 or statuses[service_name] == 201):
                svc_anonym_add_perms_url = "{magpie}/groups/{grp}/services/{svc}/permissions" \
                                           .format(magpie=magpie_url, grp=anon_group, svc=service_name)
                svc_anonym_perm_data = {"permission_name": Permission.GET_CAPABILITIES.value}
                requests.post(svc_anonym_add_perms_url, data=svc_anonym_perm_data, cookies=request_cookies, timeout=5)

            # check service response so Phoenix doesn't refuse registration
            # try with both the 'direct' URL and the 'GetCapabilities' URL
            attempt = 0
            service_info_url = "{magpie}/services/{svc}".format(magpie=magpie_url, svc=service_name)
            service_info_resp = requests.get(service_info_url, cookies=request_cookies, timeout=5)
            service_url = get_json(service_info_resp).get(service_name).get("service_url")
            svc_getcap_url = "{svc_url}/wps?service=WPS&version=1.0.0&request=GetCapabilities" \
                             .format(svc_url=service_url)
            while True:
                service_msg_direct = "Service response ({svc})".format(svc=service_name)
                service_msg_getcap = "Service response ({svc}, GetCapabilities)".format(svc=service_name)
                err, http = _request_curl(service_url, cookies=curl_cookies, msg=service_msg_direct)
                if not err and http == 200:
                    break
                err, http = _request_curl(svc_getcap_url, cookies=curl_cookies, msg=service_msg_getcap)
                if not err and http == 200:
                    break
                print_log("[{url}] Bad response from service '{svc}' retrying after {sec}s..."
                          .format(svc=service_name, url=service_url, sec=GETCAPABILITIES_INTERVAL), logger=LOGGER)
                time.sleep(GETCAPABILITIES_INTERVAL)
                attempt += 1
                if attempt >= GETCAPABILITIES_ATTEMPTS:
                    msg = "[{url}] No response from service '{svc}' after {tries} attempts. Skipping..." \
                          .format(svc=service_name, url=service_url, tries=attempt)
                    print_log(msg, logger=LOGGER)
                    break


def _magpie_update_services_conflict(conflict_services, services_dict, request_cookies):
    # type: (List[Str], ServicesSettings, AnyCookiesType) -> Dict[Str, int]
    """
    Resolve conflicting services by name during registration by updating them only if pointing to different URL.
    """
    magpie_url = get_magpie_url()
    statuses = {}
    for svc_name in conflict_services:
        statuses[svc_name] = 409
        svc_url_new = services_dict[svc_name]["url"]
        svc_url_db = "{magpie}/services/{svc}".format(magpie=magpie_url, svc=svc_name)
        svc_resp = requests.get(svc_url_db, cookies=request_cookies, timeout=5)
        svc_info = get_json(svc_resp).get(svc_name)
        svc_url_old = svc_info["service_url"]
        if svc_url_old != svc_url_new:
            svc_info["service_url"] = svc_url_new
            res_svc_put = requests.patch(svc_url_db, data=svc_info, cookies=request_cookies, timeout=5)
            statuses[svc_name] = res_svc_put.status_code
            print_log("[{url_old}] => [{url_new}] Service URL update ({svc}): {resp}"
                      .format(svc=svc_name, url_old=svc_url_old, url_new=svc_url_new, resp=res_svc_put.status_code),
                      logger=LOGGER)
    return statuses


def _magpie_register_services_with_requests(services_dict, push_to_phoenix, username, password, provider,
                                            force_update=False, disable_getcapabilities=False):
    # type: (ServicesSettings, bool, Str, Str, Str, bool, bool) -> bool
    """
    Registers :term:`Services` of loaded ``providers`` configuration using API requests.

    .. seealso::
        :func:`magpie_register_services_from_config`

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
    session = requests.Session()
    success = False
    try:
        with NamedTemporaryFile() as magpie_cookies_file:
            # Need to login first as admin
            login_url = magpie_url + SigninAPI.path
            login_data = {"user_name": username, "password": password, "provider_name": provider}
            _login_loop(login_url, magpie_cookies_file.name, login_data, "Magpie login response")
            login_resp = session.post(login_url, data=login_data)
            if login_resp.status_code != 200:
                raise_log("Failed login with specified credentials", exception=RegistrationLoginError, logger=LOGGER)
            request_cookies = login_resp.cookies

            # Register services
            # Magpie will not overwrite existing services by default, 409 Conflict instead of 201 Created
            success, statuses_register = _register_services(SERVICES_MAGPIE, services_dict,
                                                            magpie_cookies_file.name, "Magpie register service")
            # Service URL update if conflicting and requested
            if force_update and not success:
                conflict_services = [svc_name for svc_name, http_code in statuses_register.items() if http_code == 409]
                statuses_update = _magpie_update_services_conflict(conflict_services, services_dict, request_cookies)
                statuses_register.update(statuses_update)  # update previous statuses with new ones

            # Add 'GetCapabilities' permissions on newly created services to allow 'ping' from Phoenix
            # Phoenix doesn't register the service if it cannot be checked with this request
            _magpie_add_register_services_perms(services_dict, statuses_register,
                                                magpie_cookies_file.name, request_cookies, disable_getcapabilities)
            session.get(magpie_url + SignoutAPI.path)

            # Push updated services to Phoenix
            if push_to_phoenix:
                success = _phoenix_update_services(services_dict)

    except Exception as exc:
        print_log("Exception during magpie register services: [{!r}]".format(exc), logger=LOGGER, level=logging.ERROR)
    finally:
        session.cookies.clear()
    return success


def _magpie_register_services_with_db_session(services_dict, db_session, push_to_phoenix=False,
                                              force_update=False, update_getcapabilities_permissions=False):
    # type: (ServicesSettings, Session, bool, bool, bool) -> bool
    """
    Registration procedure of :term:`Services` from ``providers`` section using pre-established database session.

    .. seealso::
        :func:`magpie_register_services_from_config`
    """
    db_session.begin(subtransactions=True)
    existing_services_names = [n[0] for n in db_session.query(models.Service.resource_name)]
    magpie_anonymous_user = get_constant("MAGPIE_ANONYMOUS_USER")
    anonymous_user = UserService.by_user_name(magpie_anonymous_user, db_session=db_session)

    for svc_name, svc_values in services_dict.items():
        svc_new_url = svc_values["url"]
        svc_type = svc_values["type"]
        svc_config = svc_values.get("configuration")
        svc_sync_type = svc_values.get("sync_type")
        if force_update and svc_name in existing_services_names:
            svc = models.Service.by_service_name(svc_name, db_session=db_session)
            if svc.url == svc_new_url:
                print_log("Service URL already properly set [{url}] ({svc})"
                          .format(url=svc.url, svc=svc_name), logger=LOGGER)
            else:
                print_log("Service URL update [{url_old}] => [{url_new}] ({svc})"
                          .format(url_old=svc.url, url_new=svc_new_url, svc=svc_name),
                          logger=LOGGER, level=logging.WARN)
                svc.url = svc_new_url
            if svc.type != svc_type:
                print_log("Service type update [{type_old}] => [{type_new}] ({svc}). "
                          "If children resources/permissions are not compatible, this could break the instance."
                          .format(type_old=svc.type, type_new=svc_type, svc=svc_name),
                          logger=LOGGER, level=logging.WARN)
                svc.type = svc_type
            svc.sync_type = svc_sync_type
            svc.configuration = svc_config
        elif not force_update and svc_name in existing_services_names:
            print_log("Skipping service [{svc}] (conflict)" .format(svc=svc_name), logger=LOGGER)
        else:
            print_log("Adding service [{svc}]".format(svc=svc_name), logger=LOGGER)
            svc = models.Service(
                resource_name=svc_name,
                resource_type=models.Service.resource_type_name,
                url=svc_new_url,
                type=svc_type,
                configuration=svc_config,
                sync_type=svc_sync_type
            )
            db_session.add(svc)

        getcap_perm = Permission.GET_CAPABILITIES
        if update_getcapabilities_permissions and anonymous_user is None:
            print_log("Cannot update 'getcapabilities' permission of non existing anonymous user",
                      level=logging.WARN, logger=LOGGER)
        elif update_getcapabilities_permissions and getcap_perm in SERVICE_TYPE_DICT[svc_type].permissions:
            svc = db_session.query(models.Service.resource_id).filter_by(resource_name=svc_name).first()
            svc_perm_getcapabilities = UserResourcePermissionService.by_resource_user_and_perm(
                user_id=anonymous_user.id,
                perm_name=getcap_perm.value,
                resource_id=svc.resource_id,
                db_session=db_session
            )
            if svc_perm_getcapabilities is None:
                print_log("Adding '{}' permission to anonymous user.".format(getcap_perm.value), logger=LOGGER)
                svc_perm_getcapabilities = models.UserResourcePermission(
                    user_id=anonymous_user.id,
                    perm_name=getcap_perm.value,
                    resource_id=svc.resource_id
                )
                db_session.add(svc_perm_getcapabilities)

    transaction.commit()

    if push_to_phoenix:
        return _phoenix_update_services(services_dict)
    return True


def _load_config(path_or_dict, section, allow_missing=False):
    # type: (Union[Str, CombinedConfig], Str, bool) -> Union
    """
    Loads a YAML/JSON file path or pre-loaded dictionary configuration.
    """
    try:
        if isinstance(path_or_dict, six.string_types):
            with open(path_or_dict, mode="r", encoding="utf-8") as yml_file:
                cfg = yaml.safe_load(yml_file)
        else:
            cfg = path_or_dict
        return _expand_all(cfg[section])
    except KeyError:
        msg = "Config file section [{!s}] not found.".format(section)
        if allow_missing:
            print_log(msg, level=logging.WARNING, logger=LOGGER)
            return {}
        raise_log(msg, exception=RegistrationError, logger=LOGGER)
    except Exception as exc:
        raise_log("Invalid config file [{!r}]".format(exc), exception=RegistrationError, logger=LOGGER)


CONFIG_KNOWN_EXTENSIONS = frozenset([".cfg", ".json", ".yml", ".yaml"])


def get_all_configs(path_or_dict, section, allow_missing=False):
    # type: (Union[Str, CombinedConfig], Str, bool) -> MultiConfigs
    """
    Loads all matched configurations.

    Configurations are considered a valid match if they have one of the :py:data:`CONFIG_KNOWN_EXTENSIONS` (if path)
    and that loaded (or passed) configurations contain the specified :paramref:`section` name.

    If the input is a directory path, loads any number of files contained in it that fulfill matching conditions.
    If it is a path pointing to a single valid configuration file, loads it by itself.
    If a dictionary is passed, returns it directly if it fulfills validation.

    :param path_or_dict: directory path, file path or literal dictionary.
    :param section: section name that must be inside every matched configuration file to be loaded.
    :param allow_missing: allow to have no valid configuration after all are resolved, otherwise raises.
    :raises RegistrationError: when no valid configuration can be found and empty one is not allowed.
    :returns:
        - list of configurations loaded if input was a directory path
        - list of single configuration if input was a file path
        - list of single configuration if input was a JSON dict
        - empty list if none of the other cases where matched

    .. note::
        Order of file loading will be resolved by alphabetically sorted filename if specifying a directory path.
    """
    if isinstance(path_or_dict, six.string_types):
        if os.path.isdir(path_or_dict):
            dir_path = os.path.abspath(path_or_dict)
            cfg_names = list(sorted({fn for fn in os.listdir(dir_path)
                                     if any([fn.endswith(ext) for ext in CONFIG_KNOWN_EXTENSIONS])}))
            return [_load_config(os.path.join(dir_path, fn), section, allow_missing) for fn in cfg_names]
        if os.path.isfile(path_or_dict):
            return [_load_config(path_or_dict, section, allow_missing)]
    elif isinstance(path_or_dict, dict):
        return [_load_config(path_or_dict, section, allow_missing)]
    return []


def _expand_all(config):
    # type: (JSON) -> JSON
    """
    Applies environment variable expansion recursively to all applicable fields of a configuration definition.
    """
    if isinstance(config, dict):
        for cfg in list(config):
            cfg_key = os.path.expandvars(cfg)
            if cfg_key != cfg:
                config[cfg_key] = config.pop(cfg)
            config[cfg_key] = _expand_all(config[cfg_key])
    elif isinstance(config, (list, set)):
        for i, cfg in enumerate(config):
            config[i] = _expand_all(cfg)
    elif isinstance(config, six.string_types):
        config = os.path.expandvars(str(config))
    elif isinstance(config, (int, bool, float, type(None))):
        pass
    else:
        raise NotImplementedError("unknown parsing of config of type: {}".format(type(config)))
    return config


def magpie_register_services_from_config(service_config_path, push_to_phoenix=False, skip_registration=False,
                                         force_update=False, disable_getcapabilities=False, db_session=None):
    # type: (Str, bool, bool, bool, bool, Optional[Session]) -> ServicesSettings
    """
    Registers Magpie services from one or many `providers.cfg` file.

    Uses the provided DB session to directly update service definitions, or uses API request routes as admin. Optionally
    pushes updates to Phoenix.

    :param service_config_path: where to look for `providers` configuration(s). Directory or file path.
    :param push_to_phoenix: whether to push loaded service definitions to remote `Phoenix` service.
    :param skip_registration: Load, validate and combine :term:`Service` configurations, but don't register them.
    :param force_update: override service definitions that conflict by name with registered ones.
    :param disable_getcapabilities:
        Skip `GetCapabilities` request validation and permission update.
        By default, any service with `type` that allows `GetCapabilities` permissions will be tested to ensure it can
        be reached on the provided `url`. Once validated, this permission is applied to `anonymous` group to make its
        entrypoint accessible by anyone.
        Services that cannot have `GetCapabilities` permission are ignored regardless.
    :param db_session: Use a pre-established database connection for registration. Otherwise, API requests are employed.
    :returns: loaded service configurations.
    """
    LOGGER.info("Starting services processing.")
    services_configs = get_all_configs(service_config_path, "providers")  # type: List[ServicesConfig]
    services_config_count = len(services_configs)
    LOGGER.log(logging.INFO if services_config_count else logging.WARNING,
               "Found %s service configurations to process", services_config_count)
    merged_service_configs = {}
    for services in services_configs:
        if not services:
            LOGGER.warning("Services configuration are empty.")
            continue

        if force_update:
            merged_service_configs.update(services)
        else:
            for svc, svc_cfg in services.items():
                merged_service_configs.setdefault(svc, svc_cfg)

    merged_service_configs = validate_services_config(merged_service_configs)

    if not skip_registration:
        # register services using API POSTs
        if db_session is None:
            admin_usr = get_constant("MAGPIE_ADMIN_USER")
            admin_pwd = get_constant("MAGPIE_ADMIN_PASSWORD")
            local_provider = get_constant("MAGPIE_DEFAULT_PROVIDER")
            _magpie_register_services_with_requests(merged_service_configs, push_to_phoenix,
                                                    admin_usr, admin_pwd, local_provider,
                                                    force_update=force_update,
                                                    disable_getcapabilities=disable_getcapabilities)

        # register services directly to db using session
        else:
            _magpie_register_services_with_db_session(merged_service_configs, db_session,
                                                      push_to_phoenix=push_to_phoenix, force_update=force_update,
                                                      update_getcapabilities_permissions=not disable_getcapabilities)
    LOGGER.info("All services processed.")
    return merged_service_configs


def _handle_permission(message, permission_index, trail=", skipping...", detail=None, permission=None,
                       level=logging.WARN, raise_errors=False):
    # type: (Str, int, Str, Optional[Str], Optional[Str], Union[Str, int], bool) -> None
    """
    Logs a message related to a 'permission' entry and raises an error if required.

    Log message format is as follows (detail portion omitted if none provided)::

        {message} [permission: #{permission_index}] [{permission}]{trail}
        Detail: [{detail}]

    Such that the following logging entry is generated (omitting any additional logging formatters)::

        >> log_permission("test", 1, " skip test...", "just a test", "fake")
        test [permission: #1] [fake] skip test...
        Detail: [just a test]

    :param message: base message to log
    :param permission_index: index of the permission in the configuration list for traceability
    :param trail: trailing message appended after the base message
    :param detail: additional details appended after the trailing message after moving to another line.
    :param permission: permission name to log just before the trailing message.
    :param level: logging level (default: ``logging.WARN``)
    :param raise_errors: raises errors related to permissions, instead of just logging the info.

    .. seealso::
        `magpie/config/permissions.cfg`
    """
    trail = "{}\nDetail: [{!s}]".format(trail, detail) if detail else (trail or "")
    permission = " [{!s}]".format(permission) if permission else ""
    msg = "{} [permission #{}]{}{}".format(message, permission_index, permission, trail)
    LOGGER.log(level, msg)

    if raise_errors:
        raise RegistrationConfigurationError(msg)


def _use_request(cookies_or_session):
    return not isinstance(cookies_or_session, Session)


def _parse_resource_path(permission_config_entry,   # type: PermissionConfigItem
                         entry_index,               # type: int
                         service_info,              # type: JSON
                         cookies_or_session=None,   # type: CookiesOrSessionType
                         magpie_url=None,           # type: Optional[Str]
                         raise_errors=False         # type: bool
                         ):                         # type: (...) -> Tuple[Optional[int], bool]
    """
    Parses the `resource` field of a permission config entry and retrieves the final resource id. Creates missing
    resources as necessary if they can be automatically resolved.

    If `cookies` are provided, uses requests to a running `Magpie` instance (with ``magpie_url``) to apply permission.
    If `session` to db is provided, uses direct db connection instead to apply permission.

    :returns: tuple of found id (if any, ``None`` otherwise), and success status of the parsing operation (error)
    """
    # pylint: disable=C0415     # avoid circular imports

    if not magpie_url and _use_request(cookies_or_session):
        raise RegistrationValueError("cannot use cookies without corresponding request URL")

    resource = None
    resource_path = permission_config_entry.get("resource", "").strip("/")
    resource_type_config = permission_config_entry.get("type")
    if resource_path:
        try:
            svc_name = service_info["service_name"]
            svc_type = service_info["service_type"]

            # Prepare a list of types that fits with the list of resources
            resource_type_list = resource_type_config.strip("/").split("/") if resource_type_config else [None]
            resource_list = resource_path.split("/")
            if len(resource_type_list) == 1:
                # if only one type specified, assume every path of the resource uses the same resource type
                resource_type_list = resource_type_list * len(resource_list)
            if len(resource_list) != len(resource_type_list):
                raise RegistrationConfigurationError("Invalid resource type found in configuration : " +
                                                     permission_config_entry.get("type"))

            res_path = None
            if _use_request(cookies_or_session):
                res_path = get_magpie_url() + ServiceResourcesAPI.path.format(service_name=svc_name)
                res_resp = requests.get(res_path, cookies=cookies_or_session, timeout=5)
                svc_json = get_json(res_resp)[svc_name]  # type: JSON
                res_dict = svc_json["resources"]
            else:
                from magpie.api.management.service.service_formats import format_service_resources
                svc = models.Service.by_service_name(svc_name, db_session=cookies_or_session)
                res_dict = format_service_resources(svc, show_all_children=True, db_session=cookies_or_session)
            parent = res_dict["resource_id"]
            child_resources = res_dict["resources"]  # type: Dict[Str, JSON]
            for res, resource_type in zip(resource_list, resource_type_list):
                # search in existing children resources
                if len(child_resources):
                    res_id = list(filter(lambda r: res in [r, child_resources[r]["resource_name"]], child_resources))
                    if res_id:
                        res_info = child_resources[res_id[0]]   # type: Dict[Str, JSON]
                        child_resources = res_info["children"]  # update next sub-resource iteration
                        parent = res_info["resource_id"]
                        continue
                # missing resource, attempt creation
                svc_res_types = SERVICE_TYPE_DICT[svc_type].resource_type_names
                type_count = len(svc_res_types)
                if type_count == 0:
                    _handle_permission("Cannot generate resource", entry_index, raise_errors=True,
                                       detail="Service [{!s}] of type [{!s}] doesn't allows any sub-resource types. "
                                       .format(svc_name, svc_type))
                if type_count != 1 and not (isinstance(resource_type, six.string_types) and resource_type):
                    _handle_permission("Cannot automatically generate resource", entry_index, raise_errors=True,
                                       detail="Service [{!s}] of type [{!s}] allows more than 1 sub-resource "
                                              "types ({}). Type must be explicitly specified for auto-creation. "
                                              "Available choices are: {}"
                                       .format(svc_name, svc_type, type_count, svc_res_types))
                if type_count != 1 and resource_type not in svc_res_types:
                    _handle_permission("Cannot generate resource", entry_index, raise_errors=True,
                                       detail="Service [{!s}] of type [{!s}] allows more than 1 sub-resource "
                                              "types ({}). Specified type [{!s}] doesn't match any of the allowed "
                                              "resource types. Available choices are: {}"
                                       .format(svc_name, svc_type, type_count, resource_type, svc_res_types))
                res_type = resource_type or svc_res_types[0]
                if _use_request(cookies_or_session):
                    body = {"resource_name": res, "resource_type": res_type, "parent_id": parent}
                    resp = requests.post(res_path, json=body, cookies=cookies_or_session, timeout=5)
                else:
                    from magpie.api.management.resource.resource_utils import create_resource
                    resp = create_resource(res, res, res_type, parent, db_session=cookies_or_session)
                if resp.status_code != 201:
                    resp.raise_for_status()
                child_resources = {}
                parent = get_json(resp)["resource"]["resource_id"]
            resource = parent
            if not resource:
                raise RegistrationConfigurationError("Could not extract child resource from resource path.")
        except HTTPException as exc:
            detail = "{} ({}), {!s}".format(type(exc).__name__, exc.code, exc)
            _handle_permission("Failed resources parsing.", entry_index, detail=detail, raise_errors=raise_errors)
            return None, False
        except Exception as exc:
            _handle_permission("Failed resources parsing.", entry_index, detail=repr(exc), raise_errors=raise_errors)
            return None, False
    return resource, True


def _apply_permission_entry(permission_config_entry,    # type: PermissionConfigItem
                            entry_index,                # type: int
                            resource_id,                # type: int
                            cookies_or_session,         # type: CookiesOrSessionType
                            magpie_url,                 # type: Str
                            users,                      # type: UsersSettings
                            groups,                     # type: GroupsSettings
                            raise_errors=False,         # type: bool
                            ):                          # type: (...) -> None
    """
    Applies the single permission entry retrieved from the permission configuration.

    Assumes that permissions fields where pre-validated. Permission is applied for the user/group/resource using request
    or db session accordingly to arguments.
    """

    def _apply_request(_usr_name=None, _grp_name=None):
        # type: (Optional[Str], Optional[Str]) -> Optional[AnyResponseType]
        """
        Apply operation using HTTP request.
        """
        action_oper = None
        if usr_name:
            action_oper = UserResourcePermissionsAPI.format(user_name=_usr_name, resource_id=resource_id)
        if grp_name:
            action_oper = GroupResourcePermissionsAPI.format(group_name=_grp_name, resource_id=resource_id)
        if not action_oper:
            return None
        action_func = requests.post if create_perm else requests.delete
        action_body = {"permission": perm.json()}
        action_path = "{url}{path}".format(url=magpie_url, path=action_oper)
        action_resp = action_func(action_path, json=action_body, cookies=cookies_or_session)
        return action_resp

    def _apply_session(_usr_name=None, _grp_name=None):
        # type: (Optional[Str], Optional[Str]) -> AnyResponseType
        """
        Apply operation using db session.
        """
        # pylint: disable=C0415     # avoid circular imports
        # pylint: disable=R1705     # aligned methods are easier to read
        from magpie.api.management.group import group_utils as gt
        from magpie.api.management.user import user_utils as ut

        res = ResourceService.by_resource_id(resource_id, db_session=cookies_or_session)
        if _usr_name:
            usr = UserService.by_user_name(_usr_name, db_session=cookies_or_session)
            if create_perm:
                return ut.create_user_resource_permission_response(usr, res, perm, overwrite=True,
                                                                   db_session=cookies_or_session)
            else:
                return ut.delete_user_resource_permission_response(usr, res, perm,
                                                                   db_session=cookies_or_session)
        if _grp_name:
            grp = GroupService.by_group_name(_grp_name, db_session=cookies_or_session)
            if create_perm:
                return gt.create_group_resource_permission_response(grp, res, perm, overwrite=True,
                                                                    db_session=cookies_or_session)
            else:
                return gt.delete_group_resource_permission_response(grp, res, perm,
                                                                    db_session=cookies_or_session)

    def _apply_profile(_usr_name=None, _grp_name=None):
        # type: (Optional[Str], Optional[Str]) -> AnyResponseType
        """
        Creates the user/group profile as required.
        """
        password = pseudo_random_string(length=get_constant("MAGPIE_PASSWORD_MIN_LENGTH"))
        usr_data = {
            "user_name": _usr_name,
            "password": users.get(_usr_name, {}).get("password", password),
            "email": users.get(_usr_name, {}).get("email", "{}@mail.com".format(_usr_name)),
            "group_name": users.get(_usr_name, {}).get("group", get_constant("MAGPIE_ANONYMOUS_GROUP"))
        }
        grp_data = {
            "group_name": _grp_name,
            "description": groups.get(_grp_name, {}).get("description", ""),
            "discoverable": groups.get(_grp_name, {}).get("discoverable", False),
            "terms": groups.get(_grp_name, {}).get("terms", "")
        }
        if _use_request(cookies_or_session):
            if _usr_name:
                path = "{url}{path}".format(url=magpie_url, path=UsersAPI.path, timeout=5)
                return requests.post(path, json=usr_data, timeout=5)
            if _grp_name:
                path = "{url}{path}".format(url=magpie_url, path=GroupsAPI.path)
                return requests.post(path, json=grp_data, timeout=5)
        else:
            if _usr_name:
                from magpie.api.management.user.user_utils import create_user
                usr_data["db_session"] = cookies_or_session  # back-compatibility python 2 cannot have kw after **unpack
                return create_user(**usr_data)
            if _grp_name:
                grp_data["db_session"] = cookies_or_session  # back-compatibility python 2 cannot have kw after **unpack
                from magpie.api.management.group.group_utils import create_group
                return create_group(**grp_data)

    def _validate_response(operation, is_create, item_type="Permission"):
        # type: (Callable[[], Optional[AnyResponseType]], bool, str) -> None
        """
        Validate action/operation applied and handles raised ``HTTPException`` as returned response.
        """
        if not islambda(operation):
            raise TypeError("invalid use of method")
        try:
            _resp = operation()
            if _resp is None:
                return
        except HTTPException as exc:
            _resp = exc
        except Exception:
            raise

        # validation according to status code returned
        if is_create:
            if _resp.status_code in [200, 201]:  # update/create
                _handle_permission("{} successfully created.".format(item_type), entry_index,
                                   level=logging.INFO, trail="")
            elif _resp.status_code == 409:
                _handle_permission("{} already exists.".format(item_type), entry_index, level=logging.INFO)
            else:
                _handle_permission("Unknown response [{}]".format(_resp.status_code), entry_index,
                                   permission=permission_config_entry, level=logging.ERROR, raise_errors=raise_errors)
        else:
            if _resp.status_code == 200:
                _handle_permission("{} successfully removed.".format(item_type), entry_index,
                                   level=logging.INFO, trail="")
            elif _resp.status_code == 404:
                _handle_permission("{} already removed.".format(item_type), entry_index, level=logging.INFO)
            else:
                _handle_permission("Unknown response [{}]".format(_resp.status_code), entry_index,
                                   permission=permission_config_entry, level=logging.ERROR, raise_errors=raise_errors)

    create_perm = permission_config_entry["action"] == "create"
    perm_def = permission_config_entry["permission"]  # name or object
    usr_name = permission_config_entry.get("user")
    grp_name = permission_config_entry.get("group")
    perm = PermissionSet(perm_def)

    # process groups first as they can be referenced by user definitions
    _validate_response(lambda: _apply_profile(None, grp_name), is_create=True)
    _validate_response(lambda: _apply_profile(usr_name, None), is_create=True)
    if _use_request(cookies_or_session):
        _validate_response(lambda: _apply_request(None, grp_name), is_create=create_perm)
        _validate_response(lambda: _apply_request(usr_name, None), is_create=create_perm)
    else:
        _validate_response(lambda: _apply_session(None, grp_name), is_create=create_perm)
        _validate_response(lambda: _apply_session(usr_name, None), is_create=create_perm)


def magpie_register_permissions_from_config(permissions_config, magpie_url=None, db_session=None, raise_errors=False):
    # type: (Union[Str, PermissionsConfig], Optional[Str], Optional[Session], bool) -> None
    """
    Applies `permissions` specified in configuration(s) defined as file, directory with files or literal configuration.

    :param permissions_config: file/dir path to `permissions` config or JSON/YAML equivalent pre-loaded.
    :param magpie_url: URL to magpie instance (when using requests; default: `magpie.url` from this app's config).
    :param db_session: db session to use instead of requests to directly create/remove permissions with config.
    :param raise_errors: raises errors related to permissions, instead of just logging the info.

    .. seealso::
        `magpie/config/permissions.cfg` for specific parameters and operational details.
    """
    LOGGER.info("Starting permissions processing.")

    if _use_request(db_session):
        magpie_url = magpie_url or get_magpie_url()
        settings = {"magpie.url": magpie_url}
        LOGGER.debug("Editing permissions using requests to [%s]...", magpie_url)
        err_msg = "Invalid credentials to register Magpie permissions."
        cookies_or_session = get_admin_cookies(settings, raise_message=err_msg)
    else:
        LOGGER.debug("Editing permissions using db session...")
        cookies_or_session = db_session

    LOGGER.debug("Loading configurations.")
    permissions = get_all_configs(permissions_config, "permissions")  # type: List[PermissionsConfig]
    perms_cfg_count = len(permissions)
    LOGGER.log(logging.INFO if perms_cfg_count else logging.WARNING,
               "Found %s permissions configurations.", perms_cfg_count)
    users_settings = groups_settings = None
    if perms_cfg_count:
        users = get_all_configs(permissions_config, "users", allow_missing=True)    # type: List[UsersConfig]
        groups = get_all_configs(permissions_config, "groups", allow_missing=True)  # type: List[GroupsConfig]
        users_settings = _resolve_config_registry(users, "username") or {}
        groups_settings = _resolve_config_registry(groups, "name") or {}
    for i, perms in enumerate(permissions):
        LOGGER.info("Processing permissions from configuration (%s/%s).", i + 1, perms_cfg_count)
        _process_permissions(perms, magpie_url, cookies_or_session, users_settings, groups_settings, raise_errors)
    LOGGER.info("All permissions processed.")


def _resolve_config_registry(config_files, key):
    # type: (Optional[MultiConfigs], Str) -> AnyResolvedSettings
    """
    Converts a list of configurations entries from multiple files into a single resolved mapping.

    Resolution is accomplished against :paramref:`key` to generate the mapping of unique items.
    First configuration entries have priority over later ones if keys are duplicated.
    """
    config_map = {}
    config_files = config_files or []
    for cfg in config_files:
        if not cfg:
            continue
        if isinstance(cfg, dict):
            cfg_key = cfg.get(key, None)
            if cfg_key:
                config_map[cfg_key] = cfg
        else:
            for cfg_item in cfg:
                cfg_key = cfg_item.get(key, None)
                if cfg_key:
                    config_map[cfg_key] = cfg_item
    return config_map


def _process_permissions(permissions, magpie_url, cookies_or_session, users=None, groups=None, raise_errors=False):
    # type: (PermissionsConfig, Str, Session, Optional[UsersSettings], Optional[GroupsSettings], bool) -> None
    """
    Processes a single `permissions` configuration.
    """
    if not permissions:
        LOGGER.warning("Permissions configuration are empty.")
        return

    anon_user = get_constant("MAGPIE_ANONYMOUS_USER")
    perm_count = len(permissions)
    LOGGER.log(logging.INFO if perm_count else logging.WARNING,
               "Found %s permissions to evaluate from configuration.", perm_count)
    for i, perm_cfg in enumerate(permissions):
        # parameter validation
        if not isinstance(perm_cfg, dict) or not all(f in perm_cfg for f in ["permission", "service"]):
            _handle_permission("Invalid permission format for [{!s}]".format(perm_cfg), i, raise_errors=raise_errors)
            continue
        try:
            perm = PermissionSet(perm_cfg["permission"])
        except (ValueError, TypeError):
            perm = None
        if not perm:
            _handle_permission("Unknown permission [{!s}]".format(perm_cfg["permission"]), i, raise_errors=raise_errors)
            continue
        usr_name = perm_cfg.get("user")
        grp_name = perm_cfg.get("group")
        if not any([usr_name, grp_name]):
            _handle_permission("Missing required user and/or group field.", i, raise_errors=raise_errors)
            continue
        if usr_name == anon_user:
            _handle_permission("Skipping forbidden user permission (reserved special user: {}).".format(anon_user), i)
            continue
        if "action" not in perm_cfg:
            _handle_permission("Unspecified action", i, trail="using default (create)...", raise_errors=raise_errors)
            perm_cfg["action"] = "create"
        if perm_cfg["action"] not in ["create", "remove"]:
            _handle_permission("Unknown action [{!s}]".format(perm_cfg["action"]), i, raise_errors=raise_errors)
            continue

        # retrieve service for permissions validation
        svc_name = perm_cfg["service"]
        if _use_request(cookies_or_session):
            svc_path = magpie_url + ServiceAPI.path.format(service_name=svc_name)
            svc_resp = requests.get(svc_path, cookies=cookies_or_session, timeout=5)
            if svc_resp.status_code != 200:
                _handle_permission("Unknown service [{!s}]".format(svc_name), i, raise_errors=raise_errors)
                continue
            service_info = get_json(svc_resp)[svc_name]
        else:
            transaction.commit()    # force any pending transaction to be applied to find possible dependencies
            svc = models.Service.by_service_name(svc_name, db_session=cookies_or_session)
            if not svc:
                _handle_permission("Unknown service [{!s}]. Can't edit permissions without service.".format(svc_name),
                                   i, raise_errors=raise_errors)
                continue
            from magpie.api.management.service.service_formats import format_service
            service_info = format_service(svc)

        # apply permission config
        resource_id, found = _parse_resource_path(perm_cfg, i, service_info, cookies_or_session, magpie_url,
                                                  raise_errors)
        if found:
            if not resource_id:
                resource_id = service_info["resource_id"]
            _apply_permission_entry(perm_cfg, i, resource_id, cookies_or_session, magpie_url, users, groups,
                                    raise_errors)

    if not _use_request(cookies_or_session):
        transaction.commit()
    LOGGER.info("Done processing permissions configuration.")


def pseudo_random_string(length=8, allow_chars=string.ascii_letters + string.digits):
    # type: (int, Str) -> Str
    """
    Generate a string made of random characters.
    """
    rnd = random.SystemRandom()
    return "".join(rnd.choice(allow_chars) for _ in range(length))
