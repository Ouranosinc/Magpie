from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound, HTTPOk, HTTPBadRequest,HTTPTemporaryRedirect
import json


@view_config(route_name='get_user')
def get_user(request):
    try:
        user = request.user
        json_response = {'authenticated': 'True',
                         'name': user.user_name,
                         'email': user.email,
                         'group': [group.group_name for group in user.groups]}
        return HTTPOk(
            body=json.dumps(json_response),
            content_type='application/json')
    except:
        raise HTTPBadRequest()
