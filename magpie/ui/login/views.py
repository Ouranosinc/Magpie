import requests
from pyramid.httpexceptions import (
    HTTPException,
    HTTPFound,
    HTTPInternalServerError,
    HTTPOk,
    HTTPUnauthorized
)
from pyramid.renderers import render_to_response
from pyramid.response import Response
from pyramid.security import NO_PERMISSION_REQUIRED, forget
from pyramid.view import view_config

from magpie.api import schemas
from magpie.ui.utils import AdminRequests, BaseViews, check_response, handle_errors, request_api
from magpie.utils import get_json


class LoginViews(AdminRequests, BaseViews):
    """
    Handles UI operations related to login to, logout from, or registration of user accounts.

    .. warning::
        Admin requests are applicable only when using the temporary login.
        The temporary session is handled by dispatching operations to :class:`AdminRequest`.
        Only those methods should work with elevated session to ensure that returning those views in this class
        are back to unauthenticated level access.
    """

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

        return_data = {
            "is_registration": True,  # require login as admin for registration, dispatch operation checks
            "MAGPIE_SUB_TITLE": "User Registration",  # avoid default referring to administration operations
        }
        return_data = self.create_user_default_template_data(return_data)

        if "create" in self.request.POST:
            # delegate form submission to validation and creation
            return_data = self.create_user(return_data)
            forget(self.request)  # sanity check, remove any left over session cookies
            if return_data["is_error"]:
                return self.add_template_data(return_data)
            # successful submission of user registration
            # regardless of the combination of registration steps enabled, first is to validate email
            return_data.update({
                "message":
                    "User registration successfully submitted. "
                    "Please confirm your email address by visiting the link that was sent to the submitted email."
            })
            data = self.add_template_data(return_data)
            return render_to_response("magpie.ui.home:templates/message.mako", data, request=self.request)
        # first page load or refresh
        return self.add_template_data(return_data)
