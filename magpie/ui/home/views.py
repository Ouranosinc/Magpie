from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound, HTTPOk, HTTPBadRequest,HTTPTemporaryRedirect
import requests

@view_config(route_name='home', renderer='templates/home/home.mako')
def home_view(request):
    magpie_url = request.registry.settings['magpie.url']
    session = requests.get(magpie_url+'/session', cookies=request.cookies)
    if session.status_code == 200:
        json_data = session.json()
        if json_data['authenticated']:
            return {'user_name': json_data['user_name']}

    return dict()


@view_config(route_name='test')
def test_view(request):
    return HTTPOk()
