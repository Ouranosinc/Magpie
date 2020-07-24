from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.view import view_config

from magpie.ui.utils import BaseViews
from magpie.utils import get_json


class HomeViews(BaseViews):
    @view_config(route_name="home", renderer="templates/home.mako", permission=NO_PERMISSION_REQUIRED)
    @view_config(route_name="home_ui", renderer="templates/home.mako", permission=NO_PERMISSION_REQUIRED)
    def home_view(self):
        return self.add_template_data()

    @view_config(route_name="error", renderer="templates/error.mako", permission=NO_PERMISSION_REQUIRED)
    def error_view(self):
        data = {}
        if self.request.method == "POST":
            data = get_json(self.request)
        return self.add_template_data(data)
