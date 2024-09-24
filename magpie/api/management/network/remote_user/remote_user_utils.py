from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPForbidden, HTTPNotFound

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
    """
    Return the `NetworkRemoteUser` with the same name as ``remote_user_name`` associated
    with the ``NetworkNode`` named ``node_name``.
    """
    return (db_session.query(models.NetworkRemoteUser)
                      .join(models.NetworkNode)
                      .filter(models.NetworkRemoteUser.name == remote_user_name)
                      .filter(models.NetworkNode.name == node_name)
                      .one())


def requested_remote_user(request):
    # type: (Request) -> models.NetworkRemoteUser
    """
    Return the ``NetworkRemoteUser`` identified by the request path.

    For example: if the current request contains the path ``/nodes/nodeA/remote_users/userB``
    this will return the ``NetworkRemoteUser`` with the name userB that is associated
    with the ``NetworkNode`` with the name nodeA.
    """
    node_name = ar.get_value_matchdict_checked(request, "node_name")
    remote_user_name = ar.get_value_matchdict_checked(request, "remote_user_name")
    remote_user = ax.evaluate_call(
        lambda: _remote_user_from_names(node_name, remote_user_name, request.db),
        http_error=HTTPNotFound,
        msg_on_fail=s.NetworkRemoteUser_GET_NotFoundResponseSchema.description)
    return remote_user


def check_remote_user_access_permissions(request, remote_user=None):
    # type: (Request, Optional[models.NetworkRemoteUser]) -> None
    """
    Raises an error if the currently logged-in user has permission to view/modify the ``remote_user`` model.
    If ``remote_user`` is None, the requested remote user will be extracted from the request path.

    Admins are allowed to access any model. Other users are only allowed to access those that they are associated
    with.
    """
    if remote_user is None:
        remote_user = requested_remote_user(request)
    admin_group = get_constant("MAGPIE_ADMIN_GROUP", settings_container=request)
    is_admin = admin_group in [group.group_name for group in request.user.groups]
    if remote_user.user is None:
        associated_user = remote_user.network_node.anonymous_user(request.db)
    else:
        associated_user = remote_user.user
    is_logged_user = request.user.user_name == associated_user.user_name
    if not (is_admin or is_logged_user):
        # admins can access any remote user, other users can only delete remote users associated with themselves
        ax.raise_http(http_error=HTTPForbidden,
                      detail=s.HTTPForbiddenResponseSchema.description)
