import jwt
import requests
from pyramid.httpexceptions import (
    HTTPBadRequest,
    HTTPCreated,
    HTTPForbidden,
    HTTPFound,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPOk
)
from pyramid.security import Authenticated
from pyramid.view import view_config
from six.moves.urllib import parse as up

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.network.network_utils import decode_jwt, encode_jwt
from magpie.api.management.network.node.network_node_utils import (
    check_network_node_info,
    create_associated_user_groups,
    delete_network_node,
    load_redirect_uris,
    update_associated_user_groups
)
from magpie.api.requests import check_network_mode_enabled
from magpie.constants import get_constant


@s.NetworkNodesAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkNodes_GET_responses)
@view_config(route_name=s.NetworkNodesAPI.name, request_method="GET",
             decorator=check_network_mode_enabled, permission=Authenticated)
def get_network_nodes_view(request):
    is_admin = False
    if request.user is not None:
        admin_group = get_constant("MAGPIE_ADMIN_GROUP", settings_container=request)
        is_admin = admin_group in [group.group_name for group in request.user.groups]
    nodes = [n.as_dict() for n in request.db.query(models.NetworkNode).all()]
    if not is_admin:
        nodes = [{"name": n["name"]} for n in nodes]
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNodes_GET_OkResponseSchema.description,
                         content={"nodes": nodes})


@s.NetworkNodeAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkNode_GET_responses)
@view_config(route_name=s.NetworkNodeAPI.name, request_method="GET", decorator=check_network_mode_enabled)
def get_network_node_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_NotFoundResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNode_GET_OkResponseSchema.description,
                         content=node.as_dict())


@s.NetworkNodesAPI.post(schema=s.NetworkNode_POST_RequestSchema, tags=[s.NetworkTag],
                        response_schemas=s.NetworkNodes_POST_responses)
@view_config(route_name=s.NetworkNodesAPI.name, request_method="POST", decorator=check_network_mode_enabled)
def post_network_nodes_view(request):
    required_params = ("name", "base_url", "jwks_url", "token_url", "authorization_url")
    kwargs = {}
    for param in required_params:
        value = ar.get_multiformat_body(request, param, default=None)
        if value is None:
            ax.raise_http(http_error=HTTPBadRequest, detail=s.BadRequestResponseSchema.description)
        kwargs[param] = value
    redirect_uris = ar.get_multiformat_body(request, "redirect_uris", default=None)
    if redirect_uris is not None:
        kwargs["redirect_uris"] = load_redirect_uris(redirect_uris, request)
    check_network_node_info(request.db, **kwargs)

    node = models.NetworkNode(**kwargs)
    request.db.add(node)
    create_associated_user_groups(node, request)
    return ax.valid_http(http_success=HTTPCreated, detail=s.NetworkNodes_POST_CreatedResponseSchema.description)


@s.NetworkNodeAPI.patch(schema=s.NetworkNode_PATCH_RequestSchema,
                        tags=[s.NetworkTag], response_schemas=s.NetworkNode_PATCH_responses)
@view_config(route_name=s.NetworkNodeAPI.name, request_method="PATCH", decorator=check_network_mode_enabled)
def patch_network_node_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_NotFoundResponseSchema.description)
    params = ("name", "base_url", "jwks_url", "token_url", "authorization_url", "redirect_uris")
    kwargs = {}
    for param in params:
        param_value = ar.get_multiformat_body(request, param, default=None)
        if param_value is not None:
            if param == "redirect_uris":
                kwargs[param] = load_redirect_uris(param_value, request)
            else:
                kwargs[param] = param_value
    if not kwargs:
        ax.raise_http(http_error=HTTPBadRequest, detail=s.NetworkNodes_PATCH_BadRequestResponseSchema.description)

    check_network_node_info(request.db, **kwargs)

    for attr, value in kwargs.items():
        setattr(node, attr, value)

    update_associated_user_groups(node, node_name, request)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNode_PATCH_OkResponseSchema.description)


@s.NetworkNodeAPI.delete(tags=[s.NetworkTag], response_schemas=s.NetworkNode_DELETE_responses)
@view_config(route_name=s.NetworkNodeAPI.name, request_method="DELETE", decorator=check_network_mode_enabled)
def delete_network_node_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_NotFoundResponseSchema.description)
    ax.evaluate_call(lambda: delete_network_node(request, node),
                     http_error=HTTPInternalServerError,
                     fallback=lambda: request.db.rollback(),
                     msg_on_fail=s.InternalServerErrorResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNode_DELETE_OkResponseSchema.description)


@s.NetworkNodeTokenAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkNodeToken_GET_responses)
@view_config(route_name=s.NetworkNodeTokenAPI.name, request_method="GET",
             decorator=check_network_mode_enabled, permission=Authenticated)
def get_network_node_token_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_NotFoundResponseSchema.description)
    token = encode_jwt({"user_name": request.user.user_name}, node_name, request)
    access_token = ax.evaluate_call(lambda: requests.post(node.token_url,
                                                          json={"token": token},
                                                          timeout=5).json()["token"],
                                    http_error=HTTPInternalServerError,
                                    msg_on_fail=s.NetworkNodeToken_GET_InternalServerErrorResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, content={"token": access_token},
                         detail=s.NetworkNodeToken_GET_OkResponseSchema)


@s.NetworkNodeTokenAPI.delete(tags=[s.NetworkTag], response_schemas=s.NetworkNodeToken_DELETE_responses)
@view_config(route_name=s.NetworkNodeTokenAPI.name, request_method="DELETE",
             decorator=check_network_mode_enabled, permission=Authenticated)
def delete_network_node_token_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_NotFoundResponseSchema.description)
    token = encode_jwt({"user_name": request.user.user_name}, node_name, request)
    ax.evaluate_call(lambda: requests.delete(node.token_url, json={"token": token}, timeout=5).raise_for_status(),
                     http_error=HTTPInternalServerError,
                     msg_on_fail=s.NetworkNodeToken_DELETE_InternalServerErrorResponseSchema.description)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNodeToken_DELETE_OkResponseSchema)


@s.NetworkLinkAPI.get(schema=s.NetworkLink_GET_RequestSchema, tags=[s.NetworkTag],
                      response_schemas=s.NetworkLink_GET_responses)
@view_config(route_name=s.NetworkLinkAPI.name, request_method="GET",
             decorator=check_network_mode_enabled, permission=Authenticated)
def get_network_node_link_view(request):
    token = request.GET.get("token")
    node_name = jwt.decode(token, options={"verify_signature": False}).get("iss")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_NotFoundResponseSchema.description)
    decoded_token = decode_jwt(token, node, request)
    remote_user_name = ax.evaluate_call(lambda: decoded_token["user_name"],
                                        http_error=HTTPBadRequest,
                                        msg_on_fail=s.NetworkNodeLink_GET_BadRequestResponseSchema.description)
    requesting_user_name = ax.evaluate_call(lambda: decoded_token["requesting_user_name"],
                                            http_error=HTTPBadRequest,
                                            msg_on_fail=s.NetworkNodeLink_GET_BadRequestResponseSchema.description)
    if requesting_user_name != request.user.user_name:
        ax.raise_http(HTTPForbidden, detail=s.HTTPForbiddenResponseSchema.description)
    new_remote_user = models.NetworkRemoteUser(user_id=request.user.id, network_node_id=node.id,
                                               name=remote_user_name)
    request.db.add(new_remote_user)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkNodeLink_GET_OkResponseSchema.description)


@s.NetworkNodeLinkAPI.post(tags=[s.NetworkTag], response_schemas=s.NetworkNodeLink_POST_responses)
@view_config(route_name=s.NetworkNodeLinkAPI.name, request_method="POST",
             decorator=check_network_mode_enabled, permission=Authenticated)
def post_network_node_link_view(request):
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == node_name).one(),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkNode_NotFoundResponseSchema.description
    )
    location_tuple = up.urlparse(node.authorization_url)
    location_query_list = up.parse_qsl(location_tuple.query)
    location_query_list.extend((
        ("token", encode_jwt({"user_name": request.user.user_name}, node.name, request)),
        ("response_type", "id_token"),
        ("redirect_uri", request.route_url(s.NetworkLinkAPI.name))
    ))
    location = up.urlunparse(location_tuple._replace(query=up.urlencode(location_query_list, doseq=True)))
    return ax.valid_http(http_success=HTTPFound,
                         detail=s.NetworkNodeLink_POST_FoundResponseSchema.description,
                         http_kwargs={"location": location})
