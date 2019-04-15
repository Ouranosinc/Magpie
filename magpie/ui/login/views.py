from magpie.api import schemas as schemas
from magpie.definitions.pyramid_definitions import (
    NO_PERMISSION_REQUIRED,
    view_config,
    forget,
    Response,
    HTTPOk,
    HTTPFound,
    HTTPUnauthorized,
    HTTPInternalServerError,
    HTTPException,
)
from magpie.ui.utils import check_response, request_api
from magpie.ui.home import add_template_data
from magpie.utils import get_magpie_url, get_json
import requests


class LoginViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = get_magpie_url(request.registry)

    def request_providers_json(self):
        resp = request_api(self.request, schemas.ProvidersAPI.path, "GET")
        check_response(resp)
        return get_json(resp)["providers"]

    @view_config(route_name="login", renderer="templates/login.mako", permission=NO_PERMISSION_REQUIRED)
    def login(self):
        external_providers = self.request_providers_json()["external"]
        return_data = {
            u"external_providers": external_providers,
            u"user_name_external": self.request.POST.get("user_name", u""),
            u"user_name_internal": self.request.POST.get("user_name", u""),
            u"invalid_credentials": False,
            u"error": False,
        }

        try:
            if "submit" in self.request.POST:
                data = {}
                for key in self.request.POST:
                    data[key] = self.request.POST.get(key)

                return_data[u"provider_name"] = data.get("provider_name", "").lower()
                is_external = return_data[u"provider_name"] in [p.lower() for p in external_providers]
                if is_external:
                    return_data[u"user_name_internal"] = u""
                else:
                    return_data[u"user_name_external"] = u""

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
                elif response.status_code == HTTPUnauthorized.code:
                    return_data[u"invalid_credentials"] = True
                else:
                    return_data[u"error"] = True
        except HTTPException as e:
            if e.status_code == HTTPUnauthorized.code:
                return_data[u"invalid_credentials"] = True
            else:
                return_data[u"error"] = True
        except Exception as e:
            return HTTPInternalServerError(detail=repr(e))

        return add_template_data(self.request, data=return_data)

    @view_config(route_name="logout", renderer="templates/login.mako", permission=NO_PERMISSION_REQUIRED)
    def logout(self):
        # Flush cookies and return to home
        request_api(self.request, schemas.SignoutAPI.path, "GET")
        return HTTPFound(location=self.request.route_url("home"), headers=forget(self.request))
