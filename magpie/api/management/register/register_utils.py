from typing import TYPE_CHECKING

from pyramid.httpexceptions import (
    HTTPCreated,
    HTTPConflict,
    HTTPException,
    HTTPForbidden,
    HTTPGone,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPNotImplemented
)
from ziggurat_foundations.models.services.group import GroupService

from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.management.user import user_formats as uf
from magpie.api.management.user import user_utils as uu
from magpie.api.webhooks import webhook_update_error_status
from magpie.models import Group, UserPending, UserSearchService, UserStatuses, TemporaryToken, TokenOperation
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


def register_pending_user(user_name, password, email, db_session):
    # type: (Str, Str, Str, Session) -> HTTPException
    """
    Registers a temporary user pending approval.

    Procedure and validation workflow is similar to normal user creation by an administrator, but employs reduced
    fields and different target table. Some operations are also simplified as they are not required for pending user.
    There is also no user creation :term:`Webhook` triggers as :term:`User` doesn't exist yet.

    .. seealso::
        :func:`magpie.api.management.user.user_utils.create_user`

    :return: HTTP created with relevant details if successful.
    :raises HTTPException: HTTP error with relevant details upon any failing condition.
    """
    uu.check_user_info(user_name, email, password, check_group=False)

    # check if user already exists, must not be a conflict with pending or already existing ones
    user_checked = ax.evaluate_call(lambda: UserSearchService.by_user_name(user_name=user_name,
                                                                           status=UserStatuses.all(),
                                                                           db_session=db_session),
                                    http_error=HTTPForbidden,
                                    msg_on_fail=s.User_Check_ForbiddenResponseSchema.description)
    ax.verify_param(user_checked, is_none=True, with_param=False, http_error=HTTPConflict,
                    msg_on_fail=s.RegisterUser_Check_ConflictResponseSchema.description)

    # create pending user with specified credentials
    new_user = UserPending(user_name=user_name, email=email)  # noqa
    UserSearchService.set_password(new_user, password)
    ax.evaluate_call(lambda: db_session.add(new_user), fallback=lambda: db_session.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.Users_POST_ForbiddenResponseSchema.description)
    # Fetch user to update fields
    new_user = ax.evaluate_call(lambda: UserSearchService.by_user_name(user_name, db_session=db_session),
                                http_error=HTTPForbidden,
                                msg_on_fail=s.UserNew_POST_ForbiddenResponseSchema.description)

    user_content = uf.format_user(new_user, basic_info=True)
    return ax.valid_http(http_success=HTTPCreated, detail=s.Users_POST_CreatedResponseSchema.description,
                         content={"registration": user_content})
