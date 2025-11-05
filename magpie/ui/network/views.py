from urllib.parse import urlparse

from pyramid.authentication import Authenticated
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.view import view_config

from magpie.api import schemas
from magpie.api.management.network.network_utils import encode_jwt
from magpie.api.requests import check_network_mode_enabled
from magpie.ui.utils import AdminRequests, check_response, request_api
from magpie.utils import get_json, get_logger

LOGGER = get_logger(__name__)


class NetworkViews(AdminRequests):
    @view_config(route_name="magpie.ui.network.views.NetworkViews.authorize",
                 decorator=check_network_mode_enabled,
                 renderer="templates/authorize.mako", permission=Authenticated)
    def authorize(self):
        token = self.request.GET.get("token")
        response_type = self.request.GET.get("response_type")
        redirect_uri = self.request.GET.get("redirect_uri")

        # Extend this to other response types later if needed
        if response_type != "id_token":
            raise HTTPBadRequest("Invalid response type")
        if token is None:
            raise HTTPBadRequest("Missing token")
        admin_cookies = self.get_admin_session()
        jwt_path = "{}?token={}".format(schemas.NetworkDecodeJWTAPI.path, token)
        jwt_resp = request_api(self.request, jwt_path, "GET", cookies=admin_cookies)
        check_response(jwt_resp)
        token_content = get_json(jwt_resp)["jwt_content"]

        node_name = token_content["iss"]
        node_path = schemas.NetworkNodeAPI.path.format(node_name=node_name)
        node_resp = request_api(self.request, node_path, "GET", cookies=admin_cookies)
        check_response(node_resp)
        node_details = get_json(node_resp)

        if redirect_uri not in node_details["redirect_uris"]:
            raise HTTPBadRequest("Invalid redirect URI")

        requesting_user_name = token_content.get("user_name")
        token_claims = {"requesting_user_name": requesting_user_name, "user_name": self.request.user.user_name}
        response_token = encode_jwt(token_claims, node_name, self.request)

        return self.add_template_data(data={"authorize_uri": redirect_uri,
                                            "token": response_token,
                                            "requesting_user_name": requesting_user_name,
                                            "node_name": node_name,
                                            "node_base_url": node_details["base_url"],
                                            "referrer": urlparse(self.request.referrer).hostname})
