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
                new_location = self.magpie_url + '/signin'
                data_to_send = {}
                for key in self.request.POST:
                    data_to_send[key] = self.request.POST.get(key)

                res = requests.post(new_location, data=data_to_send, allow_redirects=True)

                if res.status_code < 400:
                    logged_url = res.url
                    pyr_res = Response(body=res.content, headers=res.headers)
                    for cookie in res.cookies:
                        pyr_res.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
                    headers = pyr_res.headers

                    # case of internal signin, new location was already signin
                    # remember cookies of logged user and redirect to home
                    if res.url == new_location:
                        logged_url = self.magpie_url
                        logged_user = get_user(self.request, data_to_send['user_name'])
                        headers = remember(self.request, logged_user.id)
                    return HTTPFound(location=logged_url, headers=headers)

                elif res.status_code == 401:
                    return HTTPFound(location=self.request.route_url('login', _query=dict(authentication='Failed')),)
                else:
                    return Response(body=res.content)
        except Exception as e:
            return HTTPInternalServerError(detail=repr(e))

        return add_template_data(self.request, {u'external_providers': self.get_external_providers()})

    @view_config(route_name='logout', renderer='templates/login.mako')
    def logout(self):
        # Flush cookies and return to home
        headers = forget(self.request)
        return HTTPFound(location=self.request.route_url('home'), headers=headers)
