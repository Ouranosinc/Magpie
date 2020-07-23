from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.view import view_config

from magpie.ui.utils import BaseViews


class HomeViews(BaseViews):
    @view_config(route_name="home", renderer="templates/home.mako", permission=NO_PERMISSION_REQUIRED)
    @view_config(route_name="home_ui", renderer="templates/home.mako", permission=NO_PERMISSION_REQUIRED)
    def home_view(self):
        return self.add_template_data()
