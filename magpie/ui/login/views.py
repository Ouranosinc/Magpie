import requests
from pyramid.view import view_config
from pyramid.httpexceptions import *
from pyramid.response import Response
from pyramid.security import forget, remember
from pyramid.request import Request

from ui.management import check_res
from ui.home import add_template_data
from api_requests import get_user


class ManagementViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = self.request.registry.settings['magpie.url']

    def get_internal_providers(self):
        req = requests.get(self.magpie_url + '/providers')
        check_res(req)
        return req.json()['internal_providers']

    def get_external_providers(self):
        req = requests.get(self.magpie_url + '/providers')
        check_res(req)
        return req.json()['external_providers']

    @view_config(route_name='login', renderer='templates/login.mako')
    def login(self):
        try:
            if 'submit' in self.request.POST:
                provider_name = self.request.POST.get('provider_name', 'ziggurat')
                # Local login
                if provider_name == 'ziggurat':
                    new_location = self.magpie_url + '/signin'
                    data_to_send = {}
                    for key in self.request.POST:
                        data_to_send[key] = self.request.POST.get(key)

                    response = requests.post(new_location, data=data_to_send, allow_redirects=True)
                    if response.status_code == 200:
                        pyr_res = Response(body=response.content, headers=response.headers)
                        for cookie in response.cookies:
                            pyr_res.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
                            return HTTPFound(location=self.request.route_url('home'), headers=pyr_res.headers)
                    else:
                        return Response(body=response.content, status=response.status_code, headers=response.headers)
                else:
                    # External login
                    external_url = self.magpie_url + '/signin_external'
                    data_to_send = {}
                    for key in self.request.POST:
                        data_to_send[key] = self.request.POST.get(key)
                    response = requests.post(external_url, data=data_to_send, allow_redirects=True)
                    pyr_res = Response(body=response.content, status=response.status_code, headers=response.headers)
                    for cookie in response.cookies:
                        pyr_res.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
                    return pyr_res

        except Exception as e:
            return HTTPInternalServerError(detail=repr(e))

        return add_template_data(self.request, {u'external_providers': self.get_external_providers()})

    @view_config(route_name='logout', renderer='templates/login.mako')
    def logout(self):
        # Flush cookies and return to home
        headers = forget(self.request)
        return HTTPFound(location=self.request.route_url('home'), headers=headers)
