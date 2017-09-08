from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound, HTTPOk, HTTPBadRequest,HTTPTemporaryRedirect
from pyramid.response import Response
import requests

external_provider = ['openid',
                     'dkrz',
                     'ipsl',
                     'badc',
                     'pcmdi',
                     'smhi']


@view_config(route_name='login', renderer='templates/login/login.mako')
def login_view(request):
    magpie_url = request.registry.settings['magpie.url']
    session = requests.get(magpie_url+'/session', cookies=request.cookies)
    if session.status_code == 200:
        json_data = session.json()
        if json_data['authenticated']:
            user_name = json_data['user_name']
            return {'user_name':  user_name,
                    'external_provider': external_provider}
        else:
            if 'submit' in request.POST:
                new_location = magpie_url+'/signin'
                data_to_send = {}
                for tuple in request.POST:
                    data_to_send[tuple] = request.POST.get(tuple)
                res = requests.post(new_location, data=data_to_send)
                if res.status_code == 200:
                    pyr_res = Response(body=res.content)
                    for cookie in res.cookies:
                        #request.response.set_cookie(name=cookie.name, value=cookie.value)
                        pyr_res.set_cookie(name=cookie.name, value=cookie.value)
                    return pyr_res
                else:
                    return Response(body=res.content)



    else:
        return Response(body=session.content)

    return {'external_provider': external_provider}



@view_config(route_name='register', renderer='templates/login/register.mako')
def register_view(request):
    if 'submit' in request.POST:
        user_name = request.POST.get('user_name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        group = 'guest'

        data = {'user_name': user_name,
                'email': email,
                'password': password,
                'group_name': group}
        magpie_url = request.registry.settings['magpie.url']
        res = requests.post(magpie_url+'/users', data=data)
        if res.status_code >= 400:
            return res
        else:
            return HTTPFound(location=request.route_url('home'))

    return dict()




