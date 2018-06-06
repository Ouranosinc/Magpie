import requests
from pyramid.view import view_config
from pyramid.httpexceptions import *
from pyramid.response import Response
from pyramid.security import forget, remember, NO_PERMISSION_REQUIRED

from ui.management import check_response
from ui.home import add_template_data


class ManagementViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = self.request.registry.settings['magpie.url']

    def get_internal_providers(self):
        resp = requests.get(self.magpie_url + '/providers')
        check_response(resp)
        return resp.json()['internal_providers']

    def get_external_providers(self):
        resp = requests.get(self.magpie_url + '/providers')
        check_response(resp)
        return resp.json()['external_providers']

    @view_config(route_name='login', renderer='templates/login.mako', permission=NO_PERMISSION_REQUIRED)
    def login(self):
        return_data = {
            u'external_providers': self.get_external_providers(),
            u'invalid_username': False,
            u'invalid_password': False,
            u'user_name': self.request.POST.get('user_name', u''),
        }

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
                    if response.status_code == HTTPOk.code:
                        pyr_res = Response(body=response.content, headers=response.headers)
                        for cookie in response.cookies:
                            pyr_res.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
                            return HTTPFound(location=self.request.route_url('home'), headers=pyr_res.headers)
                    elif response.status_code in [HTTPBadRequest.code, HTTPNotAcceptable.code]:
                        return_data[u'invalid_username'] = True
                        return add_template_data(self.request, return_data)
                    elif response.status_code == HTTPUnauthorized.code:
                        return_data[u'invalid_password'] = True
                        return add_template_data(self.request, return_data)
                        #return Response(body=response.content, status=response.status_code, headers=response.headers)
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

        return add_template_data(self.request, data=return_data)

    @view_config(route_name='logout', renderer='templates/login.mako', permission=NO_PERMISSION_REQUIRED)
    def logout(self):
        # Flush cookies and return to home
        requests.get('{url}/signout'.format(url=self.magpie_url))
        return HTTPFound(location=self.request.route_url('home'), headers=forget(self.request))
