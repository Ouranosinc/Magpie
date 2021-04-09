from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPForbidden, HTTPGone, HTTPInternalServerError, HTTPNotFound, HTTPNotImplemented
from ziggurat_foundations.models.services.group import GroupService

from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.management.user import user_utils as uu
from magpie.api.webhooks import webhook_update_error_status
from magpie.models import Group, TemporaryToken, TokenOperation
from magpie.utils import CONTENT_TYPE_JSON

if TYPE_CHECKING:
    from typing import List

    from sqlalchemy.orm.session import Session

    from magpie.typedefs import Str


def handle_temporary_token(tmp_token, db_session):
    # type: (TemporaryToken, Session) -> None
    """
    Handles the operation according to the provided temporary token.
    """
    if tmp_token.expired():
        str_token = str(tmp_token.token)
        db_session.delete(tmp_token)
        ax.raise_http(HTTPGone, content={"token": str_token}, detail=s.TemporaryURL_GET_GoneResponseSchema.description)
    ax.verify_param(tmp_token.operation, is_type=True, param_compare=TokenOperation,
                    param_name="token", http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
    if tmp_token.operation == TokenOperation.GROUP_ACCEPT_TERMS:
        ax.verify_param(tmp_token.group, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        uu.assign_user_group(tmp_token.user, tmp_token.group, db_session)
    if tmp_token.operation == TokenOperation.USER_PASSWORD_RESET:
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        # TODO: reset procedure
        ax.raise_http(HTTPNotImplemented, detail="Not Implemented")
    if tmp_token.operation == TokenOperation.WEBHOOK_USER_STATUS_ERROR:
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        webhook_update_error_status(tmp_token.user.user_name)
    db_session.delete(tmp_token)


def get_discoverable_groups(db_session):
    # type: (Session) -> List[Group]
    """
    Get all existing group that are marked as publicly discoverable from the database.
    """
    groups = ax.evaluate_call(
        lambda: [grp for grp in GroupService.all(Group, db_session=db_session) if grp.discoverable],
        http_error=HTTPForbidden, msg_on_fail=s.RegisterGroups_GET_ForbiddenResponseSchema.description)
    return groups


def get_discoverable_group_by_name(group_name, db_session):
    # type: (Str, Session) -> Group
    """
    Obtains the requested discoverable group by name.

    .. note::
        For security reason, an existing group that is **NOT** discoverable will return NotFound instead of Forbidden.
        Otherwise we give an indication to a potentially non-admin user that *some group* of that name exists.

    :return: found group matched by name
    :raises HTTPNotFound: if the group cannot be found or if matched group name is not discoverable.
    """
    public_groups = get_discoverable_groups(db_session)
    found_group = ax.evaluate_call(lambda: [grp for grp in public_groups if grp.group_name == group_name],
                                   http_error=HTTPNotFound,
                                   msg_on_fail=s.RegisterGroup_NotFoundResponseSchema.description,
                                   content={"group_name": group_name})
    ax.verify_param(found_group, param_name="group_name", not_empty=True,
                    http_error=HTTPNotFound, content_type=CONTENT_TYPE_JSON,
                    msg_on_fail=s.RegisterGroup_NotFoundResponseSchema.description)
    return found_group[0]
