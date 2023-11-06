import sqlalchemy
from pyramid.httpexceptions import (
    HTTPNotFound,
    HTTPOk,
    HTTPCreated,
)
from pyramid.security import NO_PERMISSION_REQUIRED
from pyramid.view import view_config

from magpie import models
from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.management.network.network_utils import jwks, get_network_models_from_request_token


@s.NetworkTokenAPI.post(schema=s.NetworkToken_POST_RequestSchema, tags=[s.NetworkTag],
                        response_schemas=s.NetworkToken_POST_responses)
@view_config(route_name=s.NetworkTokenAPI.name, request_method="POST")
def post_network_token_view(request):
    node, network_remote_user = get_network_models_from_request_token(request, create_network_remote_user=True)
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
@view_config(route_name=s.NetworkTokenAPI.name, request_method="DELETE")
def delete_network_token_view(request):
    node, network_remote_user = get_network_models_from_request_token(request)
    if network_remote_user.network_token:
        request.db.delete(network_remote_user.network_token)
        if (network_remote_user.user.id == node.anonymous_user(request.db).id and
                sqlalchemy.inspect(network_remote_user).persisted):
            request.db.delete(network_remote_user)  # clean up unused record in the database
        return ax.valid_http(http_success=HTTPOk, detail=s.NetworkToken_DELETE_OkResponseSchema.description)
    else:
        ax.raise_http(http_error=HTTPNotFound, detail=s.NetworkNodeToken_DELETE_NotFoundResponseSchema.description)


@s.NetworkJSONWebKeySetAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkJSONWebKeySet_GET_responses)
@view_config(route_name=s.NetworkJSONWebKeySetAPI.name, request_method="GET", permission=NO_PERMISSION_REQUIRED)
def get_network_jwks_view(_request):
    return ax.valid_http(http_success=HTTPOk,
                         detail=s.NetworkJSONWebKeySet_GET_OkResponseSchema.description,
                         content=jwks().export(private_keys=False, as_dict=True))
