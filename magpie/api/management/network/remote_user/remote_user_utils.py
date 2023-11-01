from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPNotFound, HTTPForbidden

from magpie import models
from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.constants import get_constant

if TYPE_CHECKING:
    from typing import Optional
    from pyramid.request import Request
    from magpie.typedefs import Session, Str


def _remote_user_from_names(node_name, remote_user_name, db_session):
    # type: (Str, Str, Session) -> models.NetworkRemoteUser
    return (db_session.query(models.NetworkRemoteUser)
                      .join(models.NetworkNode)
                      .filter(models.NetworkRemoteUser.name == remote_user_name)
                      .filter(models.NetworkNode.name == node_name)
                      .one())


def requested_remote_user(request):
    # type: (Request) -> models.NetworkRemoteUser
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    remote_user_name = ar.get_value_matchdict_checked(request, "remote_user_name")
    remote_user = ax.evaluate_call(
        lambda: _remote_user_from_names(node_name, remote_user_name, request.db),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkRemoteUser_GET_NotFoundResponseSchema.description)
    return remote_user


def check_remote_user_access_permissions(request, remote_user=None):
    # type: (Request, Optional[models.NetworkRemoteUser]) -> None
    if remote_user is None:
        remote_user = requested_remote_user(request)
    admin_group = get_constant("MAGPIE_ADMIN_GROUP", settings_container=request)
    is_admin = admin_group in [group.group_name for group in request.user.groups]
    is_logged_user = request.user.user_name == remote_user.user.user_name
    if not (is_admin or is_logged_user):
        # admins can access any remote user, other users can only delete remote users associated with themselves
        ax.raise_http(http_error=HTTPForbidden,
                      detail=s.HTTPForbiddenResponseSchema.description)
