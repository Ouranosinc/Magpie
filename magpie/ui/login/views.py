import requests
from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound, HTTPOk, HTTPBadRequest,HTTPTemporaryRedirect
from pyramid.response import Response
from pyramid.security import forget

from ui.management import check_res
from ui.home import add_template_data

external_providers = ['openid',
                     'dkrz',
                     'ipsl',
                     'badc',
                     'pcmdi',
                     'smhi',
                      'github']


class ManagementViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = self.request.registry.settings['magpie.url']

    @view_config(route_name='login', renderer='templates/login.mako')
    def login(self):
        if 'submit' in self.request.POST:
            new_location = self.magpie_url+'/signin'
            data_to_send = {}
            for tuple in self.request.POST:
                data_to_send[tuple] = self.request.POST.get(tuple)

            res = requests.post(new_location, data=data_to_send)

            if res.status_code < 400:
                pyr_res = Response(body=res.content)
                for cookie in res.cookies:
                    pyr_res.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
                return pyr_res
            elif res.status_code == 401:
                return HTTPFound(location=self.request.route_url('login', _query=dict(authentication='Failed')),)
            else:
                return Response(body=res.content)

        return add_template_data(self.request, {'external_providers': external_providers})


    @view_config(route_name='logout', renderer='templates/login.mako')
    def logout(self):
        # Flush cookies and return to home
        headers = forget(self.request)

        return HTTPFound(location=self.request.route_url('home'), headers=headers)

