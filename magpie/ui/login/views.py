import requests
from magpie.definitions.pyramid_definitions import *
from magpie.ui.management import check_response
from magpie.ui.home import add_template_data


class LoginViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = self.request.registry.settings['magpie.url']

    def get_internal_providers(self):
        resp = requests.get(self.magpie_url + '/providers')
        check_response(resp)
        return resp.json()['providers']['internal']

    def get_external_providers(self):
        resp = requests.get(self.magpie_url + '/providers')
        check_response(resp)
        return resp.json()['providers']['external']

    @view_config(route_name='login', renderer='templates/login.mako', permission=NO_PERMISSION_REQUIRED)
    def login(self):
        return_data = {
            u'external_providers': self.get_external_providers(),
            u'invalid_credentials': False,
            u'user_name': self.request.POST.get('user_name', u''),
        }

        try:
            if 'submit' in self.request.POST:
                signin_url = '{}/signin'.format(self.magpie_url)
                data_to_send = {}
                for key in self.request.POST:
                    data_to_send[key] = self.request.POST.get(key)

                response = requests.post(signin_url, data=data_to_send, allow_redirects=True)
                if response.status_code == HTTPOk.code:
                    pyr_res = Response(body=response.content, headers=response.headers)
                    for cookie in response.cookies:
                        pyr_res.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
                    return HTTPFound(location=self.request.route_url('home'), headers=pyr_res.headers)
                else:
                    return_data[u'invalid_credentials'] = True
                    return add_template_data(self.request, return_data)
        except Exception as e:
            return HTTPInternalServerError(detail=repr(e))

        return add_template_data(self.request, data=return_data)

    @view_config(route_name='logout', renderer='templates/login.mako', permission=NO_PERMISSION_REQUIRED)
    def logout(self):
        # Flush cookies and return to home
        requests.get('{url}/signout'.format(url=self.magpie_url))
        return HTTPFound(location=self.request.route_url('home'), headers=forget(self.request))
