from pyramid.httpexceptions import HTTPBadRequest, HTTPCreated, HTTPForbidden, HTTPNotFound, HTTPOk
from pyramid.security import Authenticated
from pyramid.view import view_config

from magpie import models
from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.management.network.remote_user.remote_user_utils import (
    check_remote_user_access_permissions,
    requested_remote_user
)
from magpie.constants import protected_user_name_regex


@s.NetworkRemoteUsersAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUsers_GET_responses)
@view_config(route_name=s.NetworkRemoteUsersAPI.name, request_method="GET")
def get_network_remote_users_view(request):
    nodes = [n.as_dict() for n in request.db.query(models.NetworkRemoteUser).all()]
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUsers_GET_OkResponseSchema.description,
                         content={"nodes": nodes})


@s.NetworkRemoteUserAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUser_GET_responses)
@view_config(route_name=s.NetworkRemoteUserAPI.name, request_method="GET", permission=Authenticated)
def get_network_remote_user_view(request):
    remote_user = requested_remote_user(request)
    check_remote_user_access_permissions(request, remote_user)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUser_GET_OkResponseSchema.description,
                         content=remote_user.as_dict())


@s.NetworkRemoteUsersAPI.post(schema=s.NetworkRemoteUsers_POST_RequestSchema, tags=[s.NetworkTag],
                              response_schemas=s.NetworkRemoteUsers_POST_responses)
@view_config(route_name=s.NetworkRemoteUsersAPI.name, request_method="POST")
def post_network_remote_users_view(request):
    required_params = ("remote_user_name", "user_name", "node_name")
    for param in required_params:
        if param not in request.POST:
            ax.raise_http(http_error=HTTPBadRequest,
                          detail=s.NetworkRemoteUsers_POST_BadRequestResponseSchema.description)
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == request.POST["node_name"]).one(),
        http_error=HTTPNotFound,
        msg_on_fail="No network node with name '{}' found".format(request.POST["node_name"])
    )
    forbidden_user_names_regex = protected_user_name_regex(include_admin=False, settings_container=request)
    user_name = request.POST["user_name"]
    ax.verify_param(user_name, not_matches=True, param_compare=forbidden_user_names_regex,
                    param_name="user_name",
                    http_error=HTTPForbidden, content={"user_name": user_name},
                    msg_on_fail=s.NetworkRemoteUsers_POST_ForbiddenResponseSchema.description)
    user = ax.evaluate_call(
        lambda: request.db.query(models.User).filter(models.User.user_name == request.POST["user_name"]).one(),
        http_error=HTTPNotFound,
        msg_on_fail="No user with user_name '{}' found".format(request.POST["user_name"])
    )
    remote_user_name = request.POST["remote_user_name"]
    ax.verify_param(remote_user_name, not_empty=True,
                    param_name="remote_user_name",
                    http_error=HTTPForbidden,
                    msg_on_fail="remote_user_name is empty")
    remote_user = models.NetworkRemoteUser(user_id=user.id, network_node_id=node.id, name=remote_user_name)
    request.db.add(remote_user)
    return ax.valid_http(http_success=HTTPCreated, detail=s.NetworkRemoteUsers_POST_CreatedResponseSchema.description)


@s.NetworkRemoteUserAPI.patch(schema=s.NetworkRemoteUser_PATCH_RequestSchema,
                              tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUser_PATCH_responses)
@view_config(route_name=s.NetworkRemoteUserAPI.name, request_method="PATCH")
def patch_network_remote_user_view(request):
    update_params = [p for p in request.POST if p in ("remote_user_name", "user_name", "node_name")]
    if not update_params:
        ax.raise_http(http_error=HTTPBadRequest, detail=s.NetworkRemoteUser_PATCH_BadRequestResponseSchema.description)
    remote_user = requested_remote_user(request)
    if "remote_user_name" in request.POST:
        remote_user_name = request.POST["remote_user_name"]
        ax.verify_param(remote_user_name, not_empty=True,
                        param_name="remote_user_name",
                        http_error=HTTPForbidden,
                        msg_on_fail="remote_user_name is empty")
        remote_user.name = remote_user_name
    if "user_name" in request.POST:
        user = ax.evaluate_call(
            lambda: request.db.query(models.User).filter(models.User.user_name == request.POST["user_name"]).one(),
            http_error=HTTPNotFound,
            msg_on_fail="No user with user_name '{}' found".format(request.POST["user_name"])
        )
        remote_user.user_id = user.id
    if "node_name" in request.POST:
        node = ax.evaluate_call(
            lambda: request.db.query(models.NetworkNode).filter(
                models.NetworkNode.name == request.POST["node_name"]).one(),
            http_error=HTTPNotFound,
            msg_on_fail="No network node with name '{}' found".format(request.POST["node_name"])
        )
        remote_user.network_node_id = node.id
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUsers_PATCH_OkResponseSchema.description)


@s.NetworkRemoteUserAPI.delete(tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUser_DELETE_responses)
@view_config(route_name=s.NetworkRemoteUserAPI.name, request_method="DELETE", permission=Authenticated)
def delete_network_remote_user_view(request):
    remote_user = requested_remote_user(request)
    check_remote_user_access_permissions(request, remote_user)
    request.db.delete(remote_user)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUser_DELETE_OkResponseSchema.description)


@s.NetworkRemoteUsersCurrentAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUsersCurrent_GET_responses)
@view_config(route_name=s.NetworkRemoteUsersCurrentAPI.name, request_method="GET", permission=Authenticated)
def get_network_remote_users_current_view(request):
    nodes = [n.as_dict() for n in
             request.db.query(models.NetworkRemoteUser).filter(models.NetworkRemoteUser.user_id == request.user.id)]
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUsers_GET_OkResponseSchema.description,
                         content={"nodes": nodes})
