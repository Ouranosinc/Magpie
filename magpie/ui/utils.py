import json
from secrets import compare_digest  # noqa 'python2-secrets'
from typing import TYPE_CHECKING

import six
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPException,
    HTTPInternalServerError,
    HTTPUnprocessableEntity,
    exception_response
)
from pyramid.renderers import render_to_response
from pyramid.request import Request
from pyramid.settings import asbool
from pyramid.view import view_defaults

from magpie import __meta__
from magpie.api import schemas
from magpie.api.generic import get_exception_info, get_request_info
from magpie.api.requests import get_logged_user
from magpie.constants import get_constant
from magpie.models import UserGroupStatus
from magpie.security import mask_credentials
from magpie.utils import CONTENT_TYPE_JSON, get_header, get_json, get_logger, get_magpie_url

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Callable, Dict, List, Optional, Union

    from pyramid.response import Response

    from magpie.typedefs import JSON, AnyResponseType, CookiesType, HeadersType, Str

LOGGER = get_logger(__name__)


def check_response(response):
    # type: (AnyResponseType) -> AnyResponseType
    """
    :returns: response if the HTTP status code is successful.
    :raises HTTPError: (of appropriate type) if the response corresponds to an HTTP error code
    """
    if response.status_code >= 400:
        raise exception_response(response.status_code, body=response.text)
    return response


def request_api(request,            # type: Request
                path,               # type: Str
                method="GET",       # type: Str
                data=None,          # type: Optional[Union[JSON, Str]]
                headers=None,       # type: Optional[HeadersType]
                cookies=None,       # type: Optional[CookiesType]
                ):                  # type: (...) -> AnyResponseType
    """
    Use a pyramid sub-request to request Magpie API routes via the UI. This avoids max retries and closed connections
    when using 1 worker (eg: during tests).

    Some information is retrieved from :paramref:`request` to pass down to the sub-request (eg: cookies).
    If they are passed as argument, corresponding values will override the ones found in :paramref:`request`.

    All sub-requests to the API are assumed to be :py:data:`magpie.common.CONTENT_TYPE_JSON` unless explicitly
    overridden with :paramref:`headers`. Headers are also looked for for additional ``Set-Cookie`` header in case they
    need to be passed down to :paramref:`cookies`.

    :param request: incoming Magpie UI request that requires sub-request to Magpie API, to retrieve required details.
    :param path: local Magpie API path (relative to root without URL).
    :param method: HTTP method to send the API sub-request.
    :param data: JSON dictionary or literal string content of the request body.
    :param headers: override headers to employ for the API sub-request. Defaults to JSON Accept & Content-Type headers.
    :param cookies:
        Override cookies to employ for the API sub-request. Defaults to current logged user.
        For empty cookies (no user), explicitly provide an empty dictionary.
    """
    method = method.upper()
    extra_kwargs = {"method": method}

    if headers:
        headers = dict(headers)
    else:
        headers = {"Accept": CONTENT_TYPE_JSON, "Content-Type": CONTENT_TYPE_JSON}
    # although no body is required per-say for HEAD/GET requests, add it if missing
    # this avoid downstream errors when 'request.POST' is accessed
    # we use a plain empty byte str because empty dict `{}` or `None` cause errors on each case
    # of local/remote testing with corresponding `webtest.TestApp`/`requests.Request`
    if not data:
        data = ""
    if isinstance(data, dict) and get_header("Content-Type", headers, split=[",", ";"]) == CONTENT_TYPE_JSON:
        data = json.dumps(data)

    if hasattr(cookies, "items"):  # any dict-like implementation
        cookies = list(cookies.items())
    if cookies and isinstance(headers, dict):
        headers = list(headers.items())
        for cookie_name, cookie_value in cookies:
            headers.append(("Set-Cookie", "{}={}".format(cookie_name, cookie_value)))
    if cookies is None:
        cookies = request.cookies
    # cookies must be added to kw only if populated, iterable error otherwise
    if cookies:
        # at this point, can be either the internal RequestCookies object (from request), that we can pass directly
        # otherwise we have a list (or dict pre-converted to list items), that we must clean up
        # dict/list format happens only when explicitly overriding the input cookies to ignore request ones
        if isinstance(cookies, list):
            # cookies passed as dict/list are expected to provide only the token value without any additional details
            # must trim extra options such as Path, Domain, Max-age, etc. for Authentication to succeed
            cookies = [(name, value.split(";")[0]) for name, value in cookies]
        extra_kwargs["cookies"] = cookies

    subreq = Request.blank(path, base_url=request.application_url, headers=headers, POST=data, **extra_kwargs)
    resp = request.invoke_subrequest(subreq, use_tweens=True)
    return resp


def redirect_error(request, code=None, content=None):
    # type: (Request, int, Optional[JSON]) -> AnyResponseType
    """
    Redirects the contents to be rendered by the UI 'error' page.

    :param request: incoming request that resulted into some kind of error.
    :param code: explicit HTTP status code for the error response, extracted from contents if otherwise available.
    :param content: any body content provided as error response from the API.
    """
    path = request.route_path("error")
    path = path.replace("/magpie/", "/") if path.startswith("/magpie") else path  # avoid glob other 'magpie'
    cause = content.get("cause", {}) if isinstance(content, dict) else {}
    code = code or content.get("content", cause.get("code", 500))
    data = {"error_request": content, "error_code": code}
    return request_api(request, path, "POST", data)  # noqa


def handle_errors(func):
    # type: (Callable) -> Callable
    """
    Decorator that encapsulates the operation in a try/except block, and redirects the response to the UI error page
    with API error contents.

    In worst case scenario where the operation cannot figure out what to do with the exception response,
    raise the most basic :class:`HTTPInternalServerError` that can be formulated from available details.

    .. seealso::
        :func:`redirect_error`
    """
    def wrap(*args, **kwargs):
        # type: (Any, Any) -> Callable[[...], Any]
        view_container = None if not args and not isinstance(args[0], BaseViews) else args[0]
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            exc_name = type(exc).__name__
            detail = "{}: {}".format(exc_name, str(exc))
            exc_info = get_exception_info(exc, exception_details=True) or detail  # noqa
            with_tb = not isinstance(exc, HTTPException) or getattr(exc, "status_code", 500) >= 500
            LOGGER.error("Unexpected API error under UI operation. [%s]", exc_info, exc_info=with_tb)
            content = {}
            if view_container:
                content = get_request_info(view_container.request, default_message=detail, exception_details=True)
            if isinstance(exc_info, dict):
                if "exception" in exc_info and "exception" not in content:
                    content = exc_info
                else:
                    content["cause"] = exc_info
            # redact traceback errors (logged), such that displayed error in UI is not too verbose
            # only display full original message from HTTP related errors
            if not isinstance(exc, HTTPException) or with_tb:
                detail = "{} occurred during operation. Please refer to application logs for details.".format(exc_name)
                content["detail"] = detail
            content.setdefault("detail", detail)
            if view_container:
                return redirect_error(view_container.request, content=mask_credentials(content))
            raise HTTPInternalServerError(detail=str(exc))
    return wrap


@view_defaults(decorator=handle_errors)
class BaseViews(object):
    """
    Base methods for Magpie UI pages.
    """
    MAGPIE_FIXED_GROUP_MEMBERSHIPS = []
    """
    Special :term:`Group` memberships that cannot be edited.
    """

    MAGPIE_FIXED_GROUP_EDITS = []
    """
    Special :term:`Group` details that cannot be edited.
    """

    MAGPIE_FIXED_USERS = []
    """
    Special :term:`User` details that cannot be edited.
    """

    MAGPIE_FIXED_USERS_REFS = []
    """
    Special :term:`User` that cannot have any relationship edited.

    This includes both :term:`Group` memberships and :term:`Permission` references.
    """

    MAGPIE_USER_PWD_LOCKED = []
    """
    Special :term:`User` that *could* self-edit themselves, but is disabled since conflicting with other policies.
    """

    MAGPIE_USER_PWD_DISABLED = []
    """
    Special :term:`User` where password cannot be edited (managed by `Magpie` configuration settings).
    """

    MAGPIE_ANONYMOUS_GROUP = None
    """
    Reference to :py:data:`magpie.constants.MAGPIE_ANONYMOUS_GROUP` for convenience in UI pages.
    """

    def __init__(self, request):
        self.request = request
        self.magpie_url = get_magpie_url(self.request)
        self.ui_theme = get_constant("MAGPIE_UI_THEME", self.request)
        self.logged_user = get_logged_user(self.request)

        anonym_grp = get_constant("MAGPIE_ANONYMOUS_GROUP", settings_container=self.request)
        admin_grp = get_constant("MAGPIE_ADMIN_GROUP", settings_container=self.request)
        self.__class__.MAGPIE_FIXED_GROUP_MEMBERSHIPS = [anonym_grp]
        self.__class__.MAGPIE_FIXED_GROUP_EDITS = [anonym_grp, admin_grp]
        # special users that cannot be deleted
        anonym_usr = get_constant("MAGPIE_ANONYMOUS_USER", self.request)
        admin_usr = get_constant("MAGPIE_ADMIN_USER", self.request)
        self.__class__.MAGPIE_FIXED_USERS_REFS = [anonym_usr]
        self.__class__.MAGPIE_FIXED_USERS = [admin_usr, anonym_usr]
        self.__class__.MAGPIE_USER_PWD_LOCKED = [admin_usr]
        self.__class__.MAGPIE_USER_PWD_DISABLED = [anonym_usr, admin_usr]
        self.__class__.MAGPIE_USER_REGISTRATION_ENABLED = asbool(
            get_constant("MAGPIE_USER_REGISTRATION_ENABLED", self.request,
                         default_value=False, print_missing=True, raise_missing=False, raise_not_set=False)
        )
        self.__class__.MAGPIE_ANONYMOUS_GROUP = anonym_grp

    def add_template_data(self, data=None):
        # type: (Optional[Dict[Str, Any]]) -> Dict[Str, Any]
        """
        Adds required template data for the 'heading' mako template applied to every UI page.
        """
        all_data = data or {}
        all_data.update({
            "MAGPIE_URL": self.magpie_url,
            "MAGPIE_TITLE": __meta__.__title__,
            "MAGPIE_AUTHOR": __meta__.__author__,
            "MAGPIE_VERSION": __meta__.__version__,
            "MAGPIE_SOURCE_URL": __meta__.__url__,
            "MAGPIE_DESCRIPTION": __meta__.__description__,
        })
        all_data.setdefault("MAGPIE_SUB_TITLE", "Administration")
        all_data.setdefault("MAGPIE_UI_THEME", self.ui_theme)
        all_data.setdefault("MAGPIE_FIXED_GROUP_MEMBERSHIPS", self.MAGPIE_FIXED_GROUP_MEMBERSHIPS)
        all_data.setdefault("MAGPIE_FIXED_GROUP_EDITS", self.MAGPIE_FIXED_GROUP_EDITS)
        all_data.setdefault("MAGPIE_FIXED_USERS", self.MAGPIE_FIXED_USERS)
        all_data.setdefault("MAGPIE_FIXED_USERS_REFS", self.MAGPIE_FIXED_USERS_REFS)
        all_data.setdefault("MAGPIE_USER_PWD_LOCKED", self.MAGPIE_USER_PWD_LOCKED)
        all_data.setdefault("MAGPIE_USER_PWD_DISABLED", self.MAGPIE_USER_PWD_DISABLED)
        all_data.setdefault("MAGPIE_USER_REGISTRATION_ENABLED", self.MAGPIE_USER_REGISTRATION_ENABLED)
        all_data.setdefault("MAGPIE_ANONYMOUS_GROUP", self.MAGPIE_ANONYMOUS_GROUP)
        if self.logged_user:
            all_data.update({"MAGPIE_LOGGED_USER": self.logged_user.user_name})
        return all_data

    @handle_errors
    def render(self, template, data=None):
        # type: (Str, Optional[Dict[Str, Any]]) -> Response
        """
        Render the response with an explicit Mako template reference.

        Views that are decorated by :func:`pyramid.view.view_config` or registered by
        :meth:`pyramid.config.Configurator.add_view` with a ``renderer`` parameter do not require to call this function
        as it is auto-resolved with the submitted :paramref:`data`.
        """
        data = self.add_template_data(data)
        return render_to_response(template, data, request=self.request)


class AdminRequests(BaseViews):
    """
    Regroups multiple administration-level operations to be dispatched to the API requests.
    """
    def create_user_default_template_data(self, data):
        """
        Generates all the default values for the various fields employed for display purposes of the user creation form.

        :param data: any template data that should override the defaults.
        :return: updated template data with defaults and overridden values.

        .. seealso:
            :meth:`create_user`
        """
        template_data = {
            "is_error": False,
            "invalid_user_name": False,
            "invalid_user_email": False,
            "invalid_password": False,
            # plain message 'Invalid' used as default in case pre-checks did not find anything, but API returned 400
            "reason_user_name": "Invalid",
            "reason_group_name": "Invalid",
            "reason_user_email": "Invalid",
            "reason_password": "Invalid",
            "form_user_name": "",
            "form_user_email": "",
            "user_groups": [],          # group selector for auto-assign on creation
            "is_registration": True     # switch between registration/admin creation items on template page
        }
        template_data.update(data)
        return template_data

    @handle_errors
    def get_admin_session(self):
        # type: () -> CookiesType
        """
        Temporarily login as default administrator to execute an elevated operation that the current user cannot make.

        .. warning::
            Cookies *MUST NOT* be preserved or memorized, to avoid user gaining restricted access.
            This is intended only for basic operations such as validating information.
            Care must be taken such information retrieved this way do not provide a way of non-administrator to
            indirectly infer some otherwise protected information. User sparingly.

        :returns: Cookies of the administrator login.
        """
        data = {
            "user_name": get_constant("MAGPIE_ADMIN_USER", self.request),
            "password": get_constant("MAGPIE_ADMIN_PASSWORD", self.request)
        }
        resp = request_api(self.request, schemas.SigninAPI.path, "POST", data=data, cookies={})
        check_response(resp)
        cookies = [tuple(value.split("=", 1)) for name, value in resp.headers.items() if "Set-Cookie" in name]
        return cookies

    @handle_errors
    def get_all_groups(self, first_default_group=None):
        resp = request_api(self.request, schemas.GroupsAPI.path, "GET")
        check_response(resp)
        groups = list(get_json(resp)["group_names"])
        if isinstance(first_default_group, six.string_types) and first_default_group in groups:
            groups.remove(first_default_group)
            groups.insert(0, first_default_group)
        return groups

    @handle_errors
    def get_group_info(self, group_name):
        # type: (Str) -> JSON
        path = schemas.GroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        return get_json(resp)["group"]

    @handle_errors
    def get_group_users(self, group_name, user_group_status=UserGroupStatus.ACTIVE):
        # type: (Str, UserGroupStatus) -> List[Str]
        path = schemas.GroupUsersAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path + "?status={}".format(user_group_status.value), "GET")
        check_response(resp)
        return get_json(resp)["user_names"]

    @handle_errors
    def update_group_info(self, group_name, group_info):
        # type: (Str, JSON) -> JSON
        path = schemas.GroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "PATCH", data=group_info)
        check_response(resp)
        return self.get_group_info(group_info.get("group_name", group_name))

    @handle_errors
    def delete_group(self, group_name):
        # type: (Str) -> JSON
        path = schemas.GroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "DELETE")
        check_response(resp)
        return get_json(resp)

    @handle_errors
    def get_user_groups(self, user_name, user_group_status=UserGroupStatus.ACTIVE):
        # type: (Str, UserGroupStatus) -> List[Str]
        path = schemas.UserGroupsAPI.path.format(user_name=user_name)
        resp = request_api(self.request, path + "?status={}".format(user_group_status.value), "GET")
        check_response(resp)
        return get_json(resp)["group_names"]

    @handle_errors
    def get_user_names(self):
        """
        Obtains all user names.
        """
        resp = request_api(self.request, schemas.UsersAPI.path, "GET")
        check_response(resp)
        return get_json(resp)["user_names"]

    @handle_errors
    def get_user_statuses(self, status=0):
        # type: (Union[Str, int]) -> List[Str]
        """
        Obtains all user names that have the corresponding status value.
        """
        resp = request_api(self.request, schemas.UsersAPI.path + "?status={}".format(status), "GET")
        check_response(resp)
        return get_json(resp)["user_names"]

    @handle_errors
    def get_user_emails(self):
        user_names = self.get_user_names()
        emails = []
        for user in user_names:
            path = schemas.UserAPI.path.format(user_name=user)
            resp = request_api(self.request, path, "GET")
            check_response(resp)
            user_email = get_json(resp)["user"]["email"]
            emails.append(user_email)
        return emails

    @handle_errors
    def get_user_details(self, status=None, cookies=None):
        # type: (Optional[Union[str, int]], Optional[CookiesType]) -> List[JSON]
        """
        Obtains all user details, optionally filtered to by corresponding status value.

        Employ this method to avoid multiple requests fetching individual information.

        .. seealso::
            - :meth:`get_user_emails`
            - :meth:`get_user_names`
            - :meth:`get_user_statuses`
        """
        query = "?detail=true"
        if status is not None:
            query += "&status={}".format(status)
        resp = request_api(self.request, schemas.UsersAPI.path + query, "GET", cookies=cookies)
        check_response(resp)
        return get_json(resp)["users"]

    def get_resource_types(self):
        """
        :return: dictionary of all resources as {id: 'resource_type'}
        :rtype: dict
        """
        resp = request_api(self.request, schemas.ResourcesAPI.path, "GET")
        check_response(resp)
        res_dic = get_json(resp).get("resources", {})
        res_ids = {}
        self.flatten_tree_resource(res_dic, res_ids)
        return res_ids

    @staticmethod
    def flatten_tree_resource(resource_node, resource_dict):
        """
        :param resource_node: any-level dictionary composing the resources tree
        :param resource_dict: reference of flattened dictionary across levels
        :return: flattened dictionary `resource_dict` of all {id: 'resource_type'}
        :rtype: dict
        """
        if not isinstance(resource_node, dict):
            return
        if not len(resource_node) > 0:
            return
        for res in resource_node.values():
            AdminRequests.flatten_tree_resource(res, resource_dict)
        if "resource_id" in resource_node and "resource_type" in resource_node:
            resource_dict[resource_node["resource_id"]] = resource_node["resource_type"]

    @handle_errors
    def get_services(self, cur_svc_type):
        resp = request_api(self.request, schemas.ServicesAPI.path, "GET")
        check_response(resp)
        all_services = get_json(resp)["services"]
        svc_types = list(sorted(all_services))
        if cur_svc_type not in svc_types:
            cur_svc_type = svc_types[0]
        services = all_services[cur_svc_type]
        return svc_types, cur_svc_type, services

    @handle_errors
    def get_service_data(self, service_name):
        path = schemas.ServiceAPI.path.format(service_name=service_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        return get_json(resp)["service"]

    def get_service_types(self):
        svc_types_resp = request_api(self.request, schemas.ServiceTypesAPI.path, "GET")
        return get_json(svc_types_resp)["service_types"]

    @handle_errors
    def update_service_name(self, old_service_name, new_service_name, service_push):
        svc_data = self.get_service_data(old_service_name)
        svc_data["service_name"] = new_service_name
        svc_data["resource_name"] = new_service_name
        svc_data["service_push"] = service_push
        svc_id = str(svc_data["resource_id"])
        path = schemas.ResourceAPI.path.format(resource_id=svc_id)
        resp = request_api(self.request, path, "PATCH", data=svc_data)
        check_response(resp)
        return get_json(resp)

    @handle_errors
    def update_service_url(self, service_name, new_service_url, service_push):
        svc_data = self.get_service_data(service_name)
        svc_data["service_url"] = new_service_url
        svc_data["service_push"] = service_push
        path = schemas.ServiceAPI.path.format(service_name=service_name)
        resp = request_api(self.request, path, "PATCH", data=svc_data)
        check_response(resp)
        return get_json(resp)

    @handle_errors
    def create_user(self, data):
        """
        Processes the user creation form with fields input data.

        All the fields are pre- and post-validated according to expected behaviour by the API.
        Pre-validations attempt *soft* checks to detect as many potential errors such that they can all be
        simultaneously displayed on the form, to avoid back-and-forth erroneous submissions by the user.
        Post-validations are the *hard* checks imposed by the API, which include some of the pre-checks.

        Whenever some failure occurs, returned data will contain ``is_error`` with ``True`` or ``False`` accordingly.
        Following successful request without error, the :term:`User` will be created. It is up to the calling function
        to redirect the response and further process the returned data as needed.

        :param data: initial templated data overrides according to who is initiation the user creation.
        :return: updated template data with any relevant error messages and statuses if applicable.
        :raises HTTPException: any unhandled or unknown HTTP error received from the API.

        .. seealso:
            :meth:`create_user_default_template_data`
        """
        data = self.create_user_default_template_data(data)
        user_name = self.request.POST.get("user_name")
        user_email = self.request.POST.get("email")
        password = self.request.POST.get("password")
        confirm = self.request.POST.get("confirm")
        data["form_user_name"] = user_name
        data["form_user_email"] = user_email
        data["is_error"] = True  # until proven otherwise

        group_name = None  # explicitly no group name to default with anonymous unless admin can override
        if data["is_registration"]:
            # when not admin, retrieve a temporary login to retrieve required information
            admin_cookies = self.get_admin_session()
        else:
            # admin-only operation, assign to new group inplace
            group_name = self.request.POST.get("group_name")
            # if group somehow doesn't exist, attempt to create it and transparently avoid the error
            if group_name not in data["user_groups"]:
                data = {"group_name": group_name}
                resp = request_api(self.request, schemas.GroupsAPI.path, "POST", data=data)
                if resp.status_code == HTTPConflict.code:
                    data["invalid_group_name"] = True
                    data["reason_group_name"] = "Conflict"
            admin_cookies = self.request.cookies

        # soft pre-checks
        user_details = self.get_user_details(status="all", cookies=admin_cookies)
        if user_email in [usr["email"].lower() for usr in user_details]:
            data["invalid_user_email"] = True
            data["reason_user_email"] = "Conflict"
        if user_email == "":
            data["invalid_user_email"] = True
        if len(user_name) > get_constant("MAGPIE_USER_NAME_MAX_LENGTH", self.request):
            data["invalid_user_name"] = True
            data["reason_user_name"] = "Too Long"
        if user_name in [usr["user_name"] for usr in user_details]:
            data["invalid_user_name"] = True
            data["reason_user_name"] = "Conflict"
        if user_name == "":
            data["invalid_user_name"] = True
        if password is None or isinstance(password, six.string_types) and len(password) < 1:
            data["invalid_password"] = True
        elif not compare_digest(password, confirm):
            data["invalid_password"] = True
            data["reason_password"] = "Mismatch"  # nosec: B105  # avoid false positive

        check_data = ["invalid_user_name", "invalid_user_email", "invalid_password", "invalid_group_name"]
        for check_fail in check_data:
            if data.get(check_fail, False):
                return self.add_template_data(data)

        # user creation
        payload = {
            "user_name": user_name,
            "email": user_email,
            "password": password,
            "group_name": group_name
        }
        # create as admin immediately creates the user
        # create by self-registration creates the pending user for approval
        path = schemas.RegisterUsersAPI.path if data["is_registration"] else schemas.UsersAPI.path
        resp = request_api(self.request, path, "POST", data=payload)

        # hard post checks, retrieve known errors related to fields to display messages instead of raising
        if resp.status_code in (HTTPBadRequest.code, HTTPConflict.code, HTTPUnprocessableEntity.code):
            # attempt to retrieve the API more-specific reason why the operation is invalid
            body = get_json(resp)
            param_name = body.get("param", {}).get("name")
            reason = body.get("detail", "Invalid")
            if param_name == "password":
                data["invalid_password"] = True
                data["reason_password"] = reason
                return data
            if param_name == "user_name":
                data["invalid_user_name"] = True
                data["reason_user_name"] = reason
                return data
            if param_name == "user_email":
                data["invalid_user_email"] = True
                data["reason_user_email"] = reason
                return data
            if param_name == "group_name":
                data["invalid_group_name"] = True
                data["reason_group_name"] = reason
                return data
        check_response(resp)  # raise any unhandled failure
        data["is_error"] = False  # reset validated success
        return data
