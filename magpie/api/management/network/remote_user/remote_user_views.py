from pyramid.httpexceptions import HTTPBadRequest, HTTPCreated, HTTPForbidden, HTTPNotFound, HTTPOk, HTTPUnprocessableEntity
from pyramid.security import Authenticated
from pyramid.settings import asbool
from pyramid.view import view_config

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.management.network.remote_user.remote_user_utils import (
    check_remote_user_access_permissions,
    requested_remote_user
)
from magpie.api.management.user.user_utils import USERNAME_REGEX
from magpie.api.requests import check_network_mode_enabled
from magpie.constants import protected_user_name_regex


@s.NetworkRemoteUsersAPI.get(tags=[s.NetworkTag], schema=s.NetworkRemoteUsers_GET_RequestSchema,
                             response_schemas=s.NetworkRemoteUsers_GET_responses)
@view_config(route_name=s.NetworkRemoteUsersAPI.name, request_method="GET", decorator=check_network_mode_enabled)
def get_network_remote_users_view(request):
    query = request.db.query(models.NetworkRemoteUser)
    user_name = request.GET.get("user_name")
    ax.verify_param(user_name, 
                    matches=True, 
                    param_name="user_name", 
                    param_compare=USERNAME_REGEX, 
                    http_error=HTTPUnprocessableEntity, 
                    msg_on_fail=s.Users_CheckInfo_UserNameValue_BadRequestResponseSchema.description)
    if user_name is not None:
        query = query.join(models.User).filter(models.User.user_name == user_name)
    nodes = [n.as_dict() for n in query.all()]
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUsers_GET_OkResponseSchema.description,
                         content={"remote_users": nodes})


@s.NetworkRemoteUserAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUser_GET_responses)
@view_config(route_name=s.NetworkRemoteUserAPI.name, request_method="GET",
             decorator=check_network_mode_enabled, permission=Authenticated)
def get_network_remote_user_view(request):
    remote_user = requested_remote_user(request)
    check_remote_user_access_permissions(request, remote_user)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUser_GET_OkResponseSchema.description,
                         content=remote_user.as_dict())


@s.NetworkRemoteUsersAPI.post(schema=s.NetworkRemoteUsers_POST_RequestSchema, tags=[s.NetworkTag],
                              response_schemas=s.NetworkRemoteUsers_POST_responses)
@view_config(route_name=s.NetworkRemoteUsersAPI.name, request_method="POST", decorator=check_network_mode_enabled)
def post_network_remote_users_view(request):
    required_params = ("remote_user_name", "node_name")
    kwargs = {"user_name": ar.get_multiformat_body(request, "user_name", default=None)}
    for param in required_params:
        value = ar.get_multiformat_body(request, param, default=None)
        if value is None:
            ax.raise_http(http_error=HTTPBadRequest,
                          detail=s.NetworkRemoteUsers_POST_BadRequestResponseSchema.description)
        kwargs[param] = value
    node = ax.evaluate_call(
        lambda: request.db.query(models.NetworkNode).filter(models.NetworkNode.name == kwargs["node_name"]).one(),
        http_error=HTTPNotFound,
        msg_on_fail="No network node with name '{}' found".format(kwargs["node_name"])
    )
    anonymous_user = node.anonymous_user(request.db)
    if kwargs["user_name"] is None:
        user = anonymous_user
    else:
        anonymous_regex = protected_user_name_regex(include_admin=False)
        ax.verify_param(kwargs["user_name"], not_matches=True, param_compare=anonymous_regex, param_name="user_name",
                        http_error=HTTPForbidden,
                        msg_on_fail="Cannot explicitly assign to an anonymous user.")
        user = ax.evaluate_call(
            lambda: request.db.query(models.User).filter(models.User.user_name == kwargs["user_name"]).one(),
            http_error=HTTPNotFound,
            msg_on_fail="No user with user_name '{}' found".format(kwargs["user_name"])
        )
    remote_user_name = kwargs["remote_user_name"]
    ax.verify_param(remote_user_name, not_empty=True,
                    param_name="remote_user_name",
                    http_error=HTTPForbidden,
                    msg_on_fail="remote_user_name is empty")
    if user.id == anonymous_user.id:
        user_id = None
    else:
        user_id = user.id
    remote_user = models.NetworkRemoteUser(user_id=user_id, network_node_id=node.id, name=remote_user_name)
    request.db.add(remote_user)
    return ax.valid_http(http_success=HTTPCreated, detail=s.NetworkRemoteUsers_POST_CreatedResponseSchema.description)


@s.NetworkRemoteUserAPI.patch(schema=s.NetworkRemoteUser_PATCH_RequestSchema,
                              tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUser_PATCH_responses)
@view_config(route_name=s.NetworkRemoteUserAPI.name, request_method="PATCH", decorator=check_network_mode_enabled)
def patch_network_remote_user_view(request):
    kwargs = {p: ar.get_multiformat_body(request, p, default=None) for p in
              ("remote_user_name", "user_name", "node_name", "assign_anonymous")}
    if not any(kwargs.values()):
        ax.raise_http(http_error=HTTPBadRequest, detail=s.NetworkRemoteUser_PATCH_BadRequestResponseSchema.description)
    remote_user = requested_remote_user(request)
    if kwargs["remote_user_name"]:
        remote_user_name = kwargs["remote_user_name"]
        ax.verify_param(remote_user_name, not_empty=True,
                        param_name="remote_user_name",
                        http_error=HTTPBadRequest,
                        msg_on_fail="remote_user_name is empty")
        remote_user.name = remote_user_name
    if kwargs["node_name"]:
        node = ax.evaluate_call(
            lambda: request.db.query(models.NetworkNode).filter(
                models.NetworkNode.name == kwargs["node_name"]).one(),
            http_error=HTTPNotFound,
            msg_on_fail="No network node with name '{}' found".format(kwargs["node_name"])
        )
        remote_user.network_node_id = node.id
    if kwargs["user_name"]:
        anonymous_regex = protected_user_name_regex(include_admin=False)
        ax.verify_param(kwargs["user_name"], not_matches=True, param_compare=anonymous_regex, param_name="user_name",
                        http_error=HTTPForbidden,
                        msg_on_fail="Cannot explicitly assign to an anonymous user.")
        user = ax.evaluate_call(
            lambda: request.db.query(models.User).filter(models.User.user_name == kwargs["user_name"]).one(),
            http_error=HTTPNotFound,
            msg_on_fail="No user with user_name '{}' found".format(kwargs["user_name"])
        )
        remote_user.user_id = user.id
    elif asbool(kwargs["assign_anonymous"]):
        remote_user.user_id = None
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUsers_PATCH_OkResponseSchema.description)


@s.NetworkRemoteUserAPI.delete(tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUser_DELETE_responses)
@view_config(route_name=s.NetworkRemoteUserAPI.name, request_method="DELETE",
             decorator=check_network_mode_enabled, permission=Authenticated)
def delete_network_remote_user_view(request):
    remote_user = requested_remote_user(request)
    check_remote_user_access_permissions(request, remote_user)
    request.db.delete(remote_user)
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUser_DELETE_OkResponseSchema.description)


@s.NetworkRemoteUsersCurrentAPI.get(tags=[s.NetworkTag], response_schemas=s.NetworkRemoteUsersCurrent_GET_responses)
@view_config(route_name=s.NetworkRemoteUsersCurrentAPI.name, request_method="GET",
             decorator=check_network_mode_enabled, permission=Authenticated)
def get_network_remote_users_current_view(request):
    nodes = [n.as_dict() for n in
             request.db.query(models.NetworkRemoteUser).filter(models.NetworkRemoteUser.user_id == request.user.id)]
    return ax.valid_http(http_success=HTTPOk, detail=s.NetworkRemoteUsers_GET_OkResponseSchema.description,
                         content={"remote_users": nodes})
