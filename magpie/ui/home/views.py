import requests
from pyramid.view import view_config
from home import add_template_data

@view_config(route_name='home', renderer='templates/home.mako')
def home_view(request):
    return add_template_data(request)