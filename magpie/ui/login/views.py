import requests
from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound, HTTPOk, HTTPBadRequest,HTTPTemporaryRedirect
from pyramid.response import Response

from management import check_res


external_provider = ['openid',
                     'dkrz',
                     'ipsl',
                     'badc',
                     'pcmdi',
                     'smhi']


class ManagementViews(object):
    def __init__(self, request):
        self.request = request
        self.magpie_url = self.request.registry.settings['magpie.url']

    @view_config(route_name='login', renderer='templates/login.mako')
    def login(self):
        user_name = self.request.session.get('user_name', None)
        if 'submit' in self.request.POST:
            self.request.session['user_name'] = None
            new_location = self.magpie_url+'/signin'
            data_to_send = {}
            for tuple in self.request.POST:
                data_to_send[tuple] = self.request.POST.get(tuple)
            res = requests.post(new_location, data=data_to_send)
            if res.status_code == 200:
                pyr_res = Response(body=res.content)
                for cookie in res.cookies:
                    pyr_res.set_cookie(name=cookie.name, value=cookie.value)

                return HTTPFound(self.request.route_url('home'), headers=pyr_res.headers)

            else:
                return Response(body=res.content)

        return {'user_name': user_name,
                'external_provider': external_provider}


    @view_config(route_name='logout', renderer='templates/login.mako')
    def logout(self):
        check_res(requests.get(self.magpie_url + '/signout'))

        # Flush cookies and return to home
        pyr_res = Response()
        for cookie in self.request.cookies:
            pyr_res.delete_cookie(cookie)
        return HTTPFound(self.request.route_url('home'), headers=pyr_res.headers)
