import jwt
from pyramid.authentication import Authenticated
from pyramid.httpexceptions import HTTPBadRequest
from pyramid.view import view_config

from magpie.api.management.network.network_utils import decode_jwt, encode_jwt
from magpie.models import NetworkNode
from magpie.ui.utils import BaseViews
from magpie.utils import get_logger


LOGGER = get_logger(__name__)


class NetworkViews(BaseViews):
    @view_config(route_name="authorize", renderer="templates/authorize.mako", permission=Authenticated)
    def authorize(self):
        token = self.request.GET.get("token")
        response_type = self.request.GET.get("response_type")
        redirect_uri = self.request.GET.get("redirect_uri")

        # Extend this to other response types later if needed
        if response_type != "id_token":
            raise HTTPBadRequest("Invalid response type")
        if token is None:
            raise HTTPBadRequest("Missing token")
        try:
            node_name = jwt.decode(token, options={"verify_signature": False}).get("iss")
        except jwt.exceptions.DecodeError:
            raise HTTPBadRequest("Token is improperly formatted")
        node = self.request.db.query(NetworkNode).filter(NetworkNode.name == node_name).first()
        if node is None:
            raise HTTPBadRequest("Invalid token: invalid or missing issuer claim")

        if redirect_uri not in (node.redirect_uris or "").split():
            raise HTTPBadRequest("Invalid redirect URI")

        decoded_token = decode_jwt(token, node, self.request)
        requesting_user_name = decoded_token.get("user_name")
        token_claims = {"requesting_user_name": requesting_user_name, "user_name": self.request.user.user_name}
        response_token = encode_jwt(token_claims, node.name, self.request)

        return self.add_template_data(data={"authorize_uri": redirect_uri,
                                            "token": response_token,
                                            "requesting_user_name": requesting_user_name,
                                            "node_name": node.name})
