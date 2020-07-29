import requests
from pyramid.httpexceptions import HTTPException, HTTPFound, HTTPInternalServerError, HTTPOk, HTTPUnauthorized
from pyramid.response import Response
from pyramid.security import NO_PERMISSION_REQUIRED, forget
from pyramid.view import view_config

from magpie.api import schemas
from magpie.ui.utils import BaseViews, check_response, request_api
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
