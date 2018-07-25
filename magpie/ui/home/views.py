from magpie.definitions.pyramid_definitions import *
from magpie.ui.home import add_template_data


@view_config(route_name='home', renderer='templates/home.mako', permission=NO_PERMISSION_REQUIRED)
def home_view(request):
    return add_template_data(request)
