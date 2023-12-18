import jwt
import sqlalchemy
from pyramid.httpexceptions import HTTPBadRequest, HTTPCreated, HTTPNotFound, HTTPOk
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.settings import asbool
from pyramid.view import view_config

from magpie import models
from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.management.network.network_utils import decode_jwt, get_network_models_from_request_token, jwks
from magpie.models import NetworkNode, NetworkToken


@s.NetworkTokenAPI.post(schema=s.NetworkToken_POST_RequestSchema, tags=[s.NetworkTag],
                        response_schemas=s.NetworkToken_POST_responses)
@view_config(route_name=s.NetworkTokenAPI.name, request_method="POST", permission=NO_PERMISSION_REQUIRED)
def post_network_token_view(request):
    _, network_remote_user = get_network_models_from_request_token(request, create_network_remote_user=True)
    network_token = network_remote_user.network_token
    if network_token:
        token = network_token.refresh_token()
    else:
        network_token = models.NetworkToken()
        token = network_token.refresh_token()
        request.db.add(network_token)
        network_remote_user.network_token = network_token
    return ax.valid_http(http_success=HTTPCreated, content={"token": token},
                         detail=s.NetworkToken_POST_CreatedResponseSchema.description)


@s.NetworkTokenAPI.delete(schema=s.NetworkToken_DELETE_RequestSchema, tags=[s.NetworkTag],
                          response_schemas=s.NetworkToken_DELETE_responses)
@view_config(route_name=s.NetworkTokenAPI.name, request_method="DELETE", permission=NO_PERMISSION_REQUIRED)
def delete_network_token_view(request):
    node, network_remote_user = get_network_models_from_request_token(request)
    if network_remote_user.network_token:
        request.db.delete(network_remote_user.network_token)
        if (network_remote_user.user.id == node.anonymous_user(request.db).id and
                sqlalchemy.inspect(network_remote_user).persisted):
            request.db.delete(network_remote_user)  # clean up unused record in the database
        return ax.valid_http(http_success=HTTPOk, detail=s.NetworkToken_DELETE_OkResponseSchema.description)
    ax.raise_http(http_error=HTTPNotFound, detail=s.NetworkNodeToken_DELETE_NotFoundResponseSchema.description)


@s.NetworkTokensAPI.delete(schema=s.NetworkTokens_DELETE_RequestSchema, tags=[s.NetworkTag],
                           response_schemas=s.NetworkTokens_DELETE_responses)
@view_config(route_name=s.NetworkTokensAPI.name, request_method="DELETE")
def delete_network_tokens_view(request):
    if asbool(request.GET.get("expired_only")):
        deleted = models.NetworkToken.delete_expired(request.db)
    else:
        deleted = request.db.query(NetworkToken).delete()
    anonymous_network_user_ids = [n.anonymous_user().id for n in request.db.query(models.NetworkNode).all()]
    # clean up unused records in the database (no need to keep records associated with anonymous network users)
    (request.db.query(models.NetworkRemoteUser)
     .filter(models.NetworkRemoteUser.user_id.in_(anonymous_network_user_ids))
     .filter(models.NetworkRemoteUser.network_token_id == None)  # noqa: E711 # pylint: disable=singleton-comparison
     .delete())
    return ax.valid_http(http_success=HTTPOk,
                         content={"deleted": deleted},
                         detail=s.NetworkTokens_DELETE_OkResponseSchema.description)


@s.NetworkJSONWebKeySetAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkJSONWebKeySet_GET_responses)
@view_config(route_name=s.NetworkJSONWebKeySetAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_network_jwks_view(_request):
    return ax.valid_http(http_success=HTTPOk,
                         detail=s.NetworkJSONWebKeySet_GET_OkResponseSchema.description,
                         content=jwks().export(private_keys=False, as_dict=True))


@s.NetworkDecodeJWTAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkDecodeJWT_GET_Responses)
@view_config(route_name=s.NetworkDecodeJWTAPI.name, request_method="GET")
def get_decode_jwt(request):
    token = request.GET.get("token")
    if token is None:
        raise HTTPBadRequest("Missing token")
    try:
        node_name = jwt.decode(token, options={"verify_signature": False}).get("iss")
    except jwt.exceptions.DecodeError:
        raise HTTPBadRequest("Token is improperly formatted")
    node = request.db.query(NetworkNode).filter(NetworkNode.name == node_name).first()
    if node is None:
        raise HTTPBadRequest("Invalid token: invalid or missing issuer claim")
    jwt_content = decode_jwt(token, node, request)
    return ax.valid_http(http_success=HTTPOk,
                         content={"jwt_content": jwt_content},
                         detail=s.NetworkDecodeJWT_GET_OkResponseSchema.description)
