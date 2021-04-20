from secrets import compare_digest

import requests
import six
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPException,
    HTTPFound,
    HTTPInternalServerError,
    HTTPOk,
    HTTPUnauthorized,
    HTTPUnprocessableEntity
)
from pyramid.response import Response
from pyramid.security import NO_PERMISSION_REQUIRED, forget
from pyramid.view import view_config

from magpie.api import schemas
from magpie.constants import get_constant
from magpie.ui.utils import BaseViews, check_response, handle_errors, request_api
from magpie.utils import get_json


class LoginViews(BaseViews):
    def request_providers_json(self):
        resp = request_api(self.request, schemas.ProvidersAPI.path, "GET")
        check_response(resp)
        return get_json(resp)["providers"]

    @view_config(route_name="login", renderer="templates/login.mako", permission=NO_PERMISSION_REQUIRED)
    def login(self):
        external_providers = self.request_providers_json()["external"]
        return_data = {
            "external_providers": external_providers,
            "user_name_external": self.request.POST.get("user_name", ""),
            "user_name_internal": self.request.POST.get("user_name", ""),
            "invalid_credentials": False,
            "error": False,
        }

        try:
            if "submit" in self.request.POST:
                data = {}
                for key in self.request.POST:
                    data[key] = self.request.POST.get(key)

                return_data["provider_name"] = data.get("provider_name", "").lower()
                is_external = return_data["provider_name"] in [p.lower() for p in external_providers]
                if is_external:
                    return_data["user_name_internal"] = ""
                else:
                    return_data["user_name_external"] = ""

                # keep using the external requests for external providers
                if is_external:
                    signin_url = "{}{}".format(self.magpie_url, schemas.SigninAPI.path)
                    response = requests.post(signin_url, data=data, allow_redirects=True)
                # use sub request for internal to avoid retry connection errors
                else:
                    response = request_api(self.request, schemas.SigninAPI.path, "POST", data=data)

                if response.status_code in (HTTPOk.code, HTTPFound.code):
                    if is_external:
                        pyr_res = Response(body=response.content, headers=response.headers)
                        for cookie in response.cookies:
                            pyr_res.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
                        return HTTPFound(response.url, headers=pyr_res.headers)
                    return HTTPFound(location=self.request.route_url("home"), headers=response.headers)

                if response.status_code == HTTPUnauthorized.code:
                    return_data["invalid_credentials"] = True
                else:
                    return_data["error"] = True
        except HTTPException as exc:
            if exc.status_code == HTTPUnauthorized.code:
                return_data["invalid_credentials"] = True
            else:
                return_data["error"] = True
        except Exception as exc:
            return HTTPInternalServerError(detail=repr(exc))

        return self.add_template_data(data=return_data)

    @view_config(route_name="logout", renderer="templates/login.mako", permission=NO_PERMISSION_REQUIRED)
    def logout(self):
        # Flush cookies and return to home
        request_api(self.request, schemas.SignoutAPI.path, "GET")
        return HTTPFound(location=self.request.route_url("home"), headers=forget(self.request))

    @handle_errors
    def get_group_info(self, group_name):
        path = schemas.GroupAPI.path.format(group_name=group_name)
        resp = request_api(self.request, path, "GET")
        check_response(resp)
        return get_json(resp)["group"]

    @view_config(route_name="register_user", renderer="templates/add_user.mako", permission=NO_PERMISSION_REQUIRED)
    def register_user(self):
        """
        User self-registration form results.

        .. note::
            The template employed for this form is reused for user creation by an administrator as the fields and
            validation of inputs are essentially the same. Their actual processing is different though, as in this
            case, the user attempting registration is not yet logged nor has any administrative access.

        .. seealso::
            :meth:`magpie.ui.management.views.ManagementViews.add_user`
        """

        return_data = {"invalid_user_name": False, "invalid_user_email": False, "invalid_password": False,
                       # 'Invalid' used as default in case pre-checks did not find anything, but API returned 400
                       "reason_user_name": "Invalid", "reason_group_name": "Invalid", "reason_user_email": "Invalid",
                       "reason_password": "Invalid", "form_user_name": "", "form_user_email": "",
                       "user_groups": [], "has_admin_access": False}  # disable non-admin items on template page

        if "create" in self.request.POST:
            user_name = self.request.POST.get("user_name")
            user_email = self.request.POST.get("email")
            password = self.request.POST.get("password")
            confirm = self.request.POST.get("confirm")
            return_data["form_user_name"] = user_name
            return_data["form_user_email"] = user_email

            if user_email in self.get_user_emails():
                return_data["invalid_user_email"] = True
                return_data["reason_user_email"] = "Conflict"
            if user_email == "":
                return_data["invalid_user_email"] = True
            if len(user_name) > get_constant("MAGPIE_USER_NAME_MAX_LENGTH", self.request):
                return_data["invalid_user_name"] = True
                return_data["reason_user_name"] = "Too Long"
            if user_name in self.get_user_names():
                return_data["invalid_user_name"] = True
                return_data["reason_user_name"] = "Conflict"
            if user_name == "":
                return_data["invalid_user_name"] = True
            if password is None or isinstance(password, six.string_types) and len(password) < 1:
                return_data["invalid_password"] = True
            elif not compare_digest(password, confirm):
                return_data["invalid_password"] = True
                return_data["reason_password"] = "Mismatch"  # nosec: B105  # avoid false positive

            check_data = ["invalid_user_name", "invalid_email", "invalid_password"]
            for check_fail in check_data:
                if return_data.get(check_fail, False):
                    return self.add_template_data(return_data)

            data = {
                "user_name": user_name,
                "email": user_email,
                "password": password,
                "group_name": None  # explicitly no group name to default with anonymous
            }
            resp = request_api(self.request, schemas.UsersAPI.path, "POST", data=data)
            if resp.status_code in (HTTPBadRequest.code, HTTPUnprocessableEntity.code):
                # attempt to retrieve the API more-specific reason why the operation is invalid
                body = get_json(resp)
                param_name = body.get("param", {}).get("name")
                reason = body.get("detail", "Invalid")
                if param_name == "password":
                    return_data["invalid_password"] = True
                    return_data["reason_password"] = reason
                    return self.add_template_data(return_data)
                if param_name == "user_name":
                    return_data["invalid_user_name"] = True
                    return_data["reason_user_name"] = reason
                    return self.add_template_data(return_data)
                if param_name == "user_email":
                    return_data["invalid_user_email"] = True
                    return_data["reason_user_email"] = reason
                    return self.add_template_data(return_data)
                if param_name == "group_name":
                    return_data["invalid_group_name"] = True
                    return_data["reason_group_name"] = reason
                    return self.add_template_data(return_data)
            check_response(resp)

            return HTTPFound(self.request.route_url("view_users"))

        # when the page is loaded the first time or refreshed
        return self.add_template_data(return_data)
