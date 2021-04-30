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
from pyramid.settings import asbool
from ziggurat_foundations.models.services.group import GroupService

from magpie.api import exception as ax
from magpie.api import schemas as s
from magpie.api.notifications import get_email_template, send_email
from magpie.api.management.user import user_formats as uf
from magpie.api.management.user import user_utils as uu
from magpie.api.webhooks import generate_callback_url, webhook_update_error_status
from magpie.constants import get_constant
from magpie.models import Group, UserPending, UserSearchService, UserStatuses, TemporaryToken, TokenOperation
from magpie.utils import CONTENT_TYPE_JSON, get_logger

if TYPE_CHECKING:
    from typing import List

    from pyramid.request import Request
    from sqlalchemy.orm.session import Session

    from magpie.typedefs import Str

LOGGER = get_logger(__name__)


def handle_temporary_token(tmp_token, request):
    # type: (TemporaryToken, Request) -> None
    """
    Handles the operation according to the provided temporary token.
    """
    if tmp_token.expired():
        str_token = str(tmp_token.token)
        request.db.delete(tmp_token)
        ax.raise_http(HTTPGone, content={"token": str_token}, detail=s.TemporaryURL_GET_GoneResponseSchema.description)
    ax.verify_param(tmp_token.operation, is_type=True, param_compare=TokenOperation,
                    param_name="token", http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")

    if tmp_token.operation == TokenOperation.GROUP_ACCEPT_TERMS:
        ax.verify_param(tmp_token.group, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        uu.assign_user_group(tmp_token.user, tmp_token.group, request.db)

    elif tmp_token.operation == TokenOperation.USER_PASSWORD_RESET:
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        # TODO: reset procedure
        ax.raise_http(HTTPNotImplemented, detail="Not Implemented")

    elif tmp_token.operation == TokenOperation.WEBHOOK_USER_STATUS_ERROR:
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        webhook_update_error_status(tmp_token.user.user_name)

    # User Registration Procedure - Step (3): reception of the registration email confirmation URL
    elif tmp_token.operation == TokenOperation.USER_REGISTRATION_CONFIRM_EMAIL:
        LOGGER.debug("[User Registration - Step 3] received email validation for user: [%s]", tmp_token.user.user_name)
        admin_approve = asbool(get_constant("MAGPIE_ADMIN_APPROVAL_ENABLED", request, default_value=False,
                                            print_missing=True, raise_missing=False, raise_not_set=False))
        if admin_approve:
            LOGGER.debug("[User Registration - Step 3B] moving on to request admin approval")
            request_admin_approval(tmp_token, request)
        else:
            LOGGER.debug("[User Registration - Step 3A] moving on to complete registration")
            complete_user_registration(tmp_token, request)

    # User Registration Procedure - Step (4): reception of the administrator approval URL
    elif tmp_token.operation == TokenOperation.USER_REGISTRATION_APPROVE_ADMIN:
        # FIXME: add auth requirement/check here - only admin should be allowed to confirm
        LOGGER.debug("[User Registration - Step 4] admin approved user: [%s]", tmp_token.user.user_name)
        complete_user_registration(tmp_token, request)

    request.db.delete(tmp_token)


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


def register_pending_user(user_name, email, password, request):
    # type: (Str, Str, Str, Request) -> HTTPException
    """
    Registers a temporary user pending approval.

    Procedure and validation workflow is similar to normal user creation by an administrator, but employs reduced
    fields and different target table. Some operations are also simplified as they are not required for pending user.
    There is also no user creation :term:`Webhook` triggers as :term:`User` doesn't exist yet.

    .. seealso::
        See :func:`magpie.api.management.user.user_utils.create_user` for similarities and distinctions of
        operations between a *normal* :term:`User` and a :term:`Pending User`.

    Implements steps (1) and (2) of the :ref:`proc_user_registration`.

    .. seealso::
        - see :func:`` for following steps of the procedure following reception of the confirmation email.

    :return: HTTP created with relevant details if successful.
    :raises HTTPException: HTTP error with relevant details upon any failing condition.
    """

    LOGGER.debug("[User Registration - Step 1] inputs validation of submitted registration details")
    uu.check_user_info(user_name, email, password, check_group=False)

    # check if user already exists, must not be a conflict with pending or already existing ones
    user_checked = ax.evaluate_call(lambda: UserSearchService.by_user_name(user_name=user_name,
                                                                           status=UserStatuses.all(),
                                                                           db_session=request.db),
                                    http_error=HTTPForbidden,
                                    msg_on_fail=s.User_Check_ForbiddenResponseSchema.description)
    ax.verify_param(user_checked, is_none=True, with_param=False, http_error=HTTPConflict,
                    msg_on_fail=s.RegisterUser_Check_ConflictResponseSchema.description)

    # create pending user with specified credentials
    tmp_user = UserPending(user_name=user_name, email=email)  # noqa
    UserSearchService.set_password(tmp_user, password)
    ax.evaluate_call(lambda: request.db.add(tmp_user), fallback=lambda: request.db.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.Users_POST_ForbiddenResponseSchema.description)
    # Fetch user to update fields
    tmp_user = ax.evaluate_call(lambda: UserSearchService.by_user_name(user_name, db_session=request.db),
                                http_error=HTTPForbidden,
                                msg_on_fail=s.UserNew_POST_ForbiddenResponseSchema.description)

    LOGGER.debug("[User Registration - Step 2] sending confirmation email for its validation")
    confirmation_url = generate_callback_url(TokenOperation.USER_REGISTRATION_CONFIRM_EMAIL, request.db, user=tmp_user)
    params = {"confirm_url": confirmation_url, "user": tmp_user}
    template = get_email_template("MAGPIE_USER_REGISTRATION_EMAIL_TEMPLATE", request)
    ax.evaluate_call(lambda: send_email(tmp_user.email, template, request, params),
                     fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                     msg_on_fail="Error occurred during user registration when trying to send "
                                 "email to pending user for confirmation of its submitted email.")

    user_content = uf.format_user(tmp_user, basic_info=True)
    return ax.valid_http(http_success=HTTPCreated, detail=s.Users_POST_CreatedResponseSchema.description,
                         content={"registration": user_content})


def request_admin_approval(tmp_token, request):
    # type: (TemporaryToken, Request) -> None
    """
    Sends the email to the administrator to approve or refuse the :term:`Pending User` registration.

    Implements steps (3B) of the :ref:`proc_user_registration`.
    """
    tmp_user = tmp_token.user
    LOGGER.debug("[User Registration - Step 3B] request admin approval for pending user: [%s]", tmp_user.user_name)
    validation_url = generate_callback_url(TokenOperation.USER_REGISTRATION_APPROVE_ADMIN, request.db, user=tmp_user)
    params = {"approve_url": validation_url,
              "refuse_url": "",  # FIXME: add utility endpoint - immediately invalidate pending user
              "pending_url": "",  # FIXME: ui view to display pending user - same as account, but less sections
              "user": tmp_user}
    admin_email = get_constant("MAGPIE_ADMIN_APPROVAL_EMAIL_RECIPIENT", request)
    template = get_email_template("MAGPIE_USER_REGISTRATION_EMAIL_TEMPLATE", request)
    ax.evaluate_call(lambda: send_email(admin_email, template, request, params),
                     fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                     msg_on_fail="Error occurred during user registration when trying to send "
                                 "notification email to administrator for pending user approval.")


def complete_user_registration(tmp_token, request):
    # type: (TemporaryToken, Request) -> None
    """
    Completes the successful user registration following any required validation steps.

    Generates the :term:`User` from the :term:`Pending User`.
    Then, sends any requested notification emails about successful :term:`User` creation.

    Implements steps (5) and (6) of the :ref:`proc_user_registration`.

    .. seealso::
        - :func:`register_pending_user` for initial steps that started the process.
        - :func:`request_admin_approval` for intermediate steps if approval feature was enabled.
    """
    LOGGER.debug("[User Registration - Step 5] pending user: [%s]", tmp_token.user.user_name)
    user = tmp_token.user.upgrade()
    LOGGER.debug("Pending user upgraded to full user: [%s (%s)]", user.user_name, user.id)

    notify = asbool(get_constant("MAGPIE_USER_REGISTERED_ENABLED", request, default_value=False,
                                 print_missing=True, raise_missing=False, raise_not_set=False))
    if notify:
        LOGGER.debug("[User Registration - Step 6] notify completed registration: [%s]", user.user_name)
        recipient = get_constant("MAGPIE_USER_REGISTERED_EMAIL_RECIPIENT", request)
        template = get_email_template("MAGPIE_USER_REGISTERED_EMAIL_TEMPLATE", request)
        params = {"user": user}
        ax.evaluate_call(lambda: send_email(recipient, template, request, params),
                         fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                         msg_on_fail="Error occurred during user registration when attempting to "
                                     "send notification email of completed operation.")
    LOGGER.debug("[User Registration] completed registration: [%s]", user.user_name)
