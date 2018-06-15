from api.management.group.group_utils import *
from definitions.ziggurat_definitions import *
from definitions.pyramid_definitions import view_config
from ui.api.proxy import WSGIProxyApplication
import requests

"""
@view_config(route_name='api_ui', request_method='GET')
def get_api_ui(request):
    #Proxy HTTP request to upstream server.
    #api_ui_port = int(request.registry.settings['magpie.api.port'])
    #proxy_app = WSGIProxyApplication(api_ui_port)
    #return request.get_response(proxy_app)
"""

class ManagementViews(object):
    def __init__(self, request):
        self.request = request
        #self.magpie_url = self.request.registry.settings['magpie.url']

    @view_config(route_name='api_ui', request_method='GET')
    def get_api_ui(self):
        """Proxy HTTP request to upstream server."""
        api_ui_url = self.request.registry.settings['magpie.api.url']
        return self.request.route_url()
#        return HTTPFound(self.request.route_url(api_ui_url))
#        return requests.get(api_ui_url)
        #self.request.route_url('swagger_ui')
