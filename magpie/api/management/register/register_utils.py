from inspect import cleandoc
from typing import TYPE_CHECKING

from pyramid.httpexceptions import (
    HTTPCreated,
    HTTPConflict,
    HTTPException,
    HTTPForbidden,
    HTTPGone,
    HTTPInternalServerError,
    HTTPNotFound,
    HTTPNotImplemented,
    HTTPOk
)
from pyramid.settings import asbool
from sqlalchemy import inspect as sa_inspect
from ziggurat_foundations.models.services.group import GroupService

from magpie.api import exception as ax
from magpie.api import requests as ar
from magpie.api import schemas as s
from magpie.api.notifications import get_email_template, send_email
from magpie.api.management.register import register_formats as rf
from magpie.api.management.user import user_formats as uf
from magpie.api.management.user import user_utils as uu
from magpie.api.webhooks import generate_callback_url, webhook_update_error_status
from magpie.constants import get_constant
from magpie.models import Group, UserPending, UserSearchService, UserStatuses, TemporaryToken, TokenOperation
from magpie.utils import CONTENT_TYPE_JSON, get_logger, get_magpie_url
from magpie.ui.utils import BaseViews

if TYPE_CHECKING:
    from typing import List, Union

    from pyramid.request import Request
    from pyramid.response import Response
    from sqlalchemy.orm.session import Session

    from magpie.typedefs import Str

LOGGER = get_logger(__name__)


def handle_temporary_token(tmp_token, request):
    # type: (TemporaryToken, Request) -> Union[HTTPException, Response]
    """
    Handles the operation according to the provided temporary token.

    :returns:
        Basic JSON response with successful indicate of correct handling of the token by default.
        If overridden, can be any HTML rendered response.
    """
    if tmp_token.expired():
        str_token = str(tmp_token.token)
        request.db.delete(tmp_token)
        ax.raise_http(HTTPGone, content={"token": str_token}, detail=s.TemporaryURL_GET_GoneResponseSchema.description)
    ax.verify_param(tmp_token.operation, is_type=True, param_compare=TokenOperation,
                    param_name="token", http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")

    # if any token handler needs to return a custom response (eg: UI message page), it should override this variable
    response = None

    if tmp_token.operation == TokenOperation.GROUP_ACCEPT_TERMS:
        ax.verify_param(tmp_token.group, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        uu.assign_user_group(tmp_token.user, tmp_token.group, request.db)

    elif tmp_token.operation == TokenOperation.USER_PASSWORD_RESET:
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        # TODO: password reset procedure
        ax.raise_http(HTTPNotImplemented, detail="Not Implemented")

    elif tmp_token.operation == TokenOperation.WEBHOOK_USER_STATUS_ERROR:
        ax.verify_param(tmp_token.user, not_none=True,
                        http_error=HTTPInternalServerError, msg_on_fail="Invalid token.")
        webhook_update_error_status(tmp_token.user.user_name)

    # User Registration Procedure - Step (3): reception of the registration email confirmation URL from the user
    elif tmp_token.operation == TokenOperation.USER_REGISTRATION_CONFIRM_EMAIL:
        LOGGER.debug("[User Registration - Step 3] received email validation for user: [%s]", tmp_token.user.user_name)
        response = handle_user_registration_confirmation(tmp_token, request)

    # User Registration Procedure - Step (4): reception of the administrator approve/decline URL
    elif tmp_token.operation in [TokenOperation.USER_REGISTRATION_ADMIN_APPROVE,
                                 TokenOperation.USER_REGISTRATION_ADMIN_DECLINE]:
        ax.verify_param(ar.has_admin_access(request), is_true=True, with_param=False,
                        http_error=HTTPForbidden, msg_on_fail=s.HTTPForbiddenResponseSchema.description)
        LOGGER.debug("[User Registration - Step 4] admin reviewed pending user: [%s]", tmp_token.user.user_name)
        response = handle_user_registration_admin_decision(tmp_token, request)

    else:
        ax.raise_http(HTTPInternalServerError, detail="Unhandled token operation.", content=tmp_token.json())

    # sync updated token as needed if handling operation modified it, then delete it because it was processed
    if sa_inspect(tmp_token).detached:
        tmp_token = request.db.merge(tmp_token)
    if sa_inspect(tmp_token).pending:
        tmp_token = TemporaryToken.by_token(tmp_token.token, db_session=request.db)
    request.db.delete(tmp_token)

    # generate default API success response if not overridden by specific case to indicate token was correctly handled
    if not response:
        response = ax.valid_http(http_success=HTTPOk, detail=s.TemporaryURL_GET_OkResponseSchema.description)
    return response


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

    Implements steps (1) and (2) of the user registration procedure.

    .. seealso::
        - See :ref:`proc_user_registration` for the procedure step details.
        - See :func:`request_admin_approval` and :func:`complete_user_registration` for following steps of
          the procedure following reception of the confirmation email.

    :return: HTTP created with relevant details if successful.
    :raises HTTPException: HTTP error with relevant details upon any failing condition.
    """

    LOGGER.debug("[User Registration - Step 1] inputs validation of submitted registration details")
    uu.check_user_info(user_name, email, password, check_group=False)

    # check if user already exists, must not be a conflict with pending or already existing ones
    user_checked = ax.evaluate_call(
        lambda: UserSearchService.by_name_or_email(user_name=user_name, email=email,
                                                   status=UserStatuses.all(), db_session=request.db),
        http_error=HTTPForbidden, msg_on_fail=s.User_Check_ForbiddenResponseSchema.description)
    ax.verify_param(user_checked, is_none=True, with_param=False, http_error=HTTPConflict,
                    msg_on_fail=s.RegisterUser_Check_ConflictResponseSchema.description)

    # create pending user with specified credentials
    tmp_user = UserPending(user_name=user_name, email=email)  # noqa  # https://youtrack.jetbrains.com/issue/PY-28744
    UserSearchService.set_password(tmp_user, password)
    ax.evaluate_call(lambda: request.db.add(tmp_user), fallback=lambda: request.db.rollback(),
                     http_error=HTTPForbidden, msg_on_fail=s.Users_POST_ForbiddenResponseSchema.description)
    # fetch user to retrieve auto-generated fields (i.e.: id)
    tmp_user = ax.evaluate_call(
        lambda: UserSearchService.by_user_name(user_name, status=UserStatuses.Pending, db_session=request.db),
        http_error=HTTPForbidden, msg_on_fail=s.UserNew_POST_ForbiddenResponseSchema.description)

    LOGGER.debug("[User Registration - Step 2] sending confirmation email for its validation")
    confirmation_url = generate_callback_url(TokenOperation.USER_REGISTRATION_CONFIRM_EMAIL, request.db, user=tmp_user)
    admin_approve = asbool(get_constant("MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED", request, default_value=False,
                                        print_missing=True, raise_missing=False, raise_not_set=False))
    params = {
        "user": tmp_user,
        "confirm_url": confirmation_url,
        "approval_required": admin_approve,
    }
    template = get_email_template("MAGPIE_USER_REGISTRATION_SUBMISSION_EMAIL_TEMPLATE", request)
    ax.evaluate_call(lambda: send_email(tmp_user.email, request, template, params),
                     fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                     msg_on_fail="Error occurred during user registration when trying to send "
                                 "email to pending user for confirmation of its submitted email.")

    user_content = rf.format_pending_user(tmp_user)
    return ax.valid_http(http_success=HTTPCreated, detail=s.Users_POST_CreatedResponseSchema.description,
                         content={"registration": user_content})


def handle_user_registration_confirmation(tmp_token, request):
    # type: (TemporaryToken, Request) -> Response
    """
    Applies the appropriate step of the user registration workflow following reception of the confirmation URL visit.

    Implements steps (3A) and (3B) redirection of the user registration procedure.
    Generates the appropriate response that will be displayed to the :term:`Pending User` that confirmed its email.

    .. seealso::
        - See :ref:`proc_user_registration` for the procedure step details.
        - See :ref:`request_admin_approval` for step 3B.
        - See :ref:`complete_user_registration` for step 5 (from 3A).
    """
    require_approve = asbool(get_constant("MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED", request, default_value=False,
                                          print_missing=True, raise_missing=False, raise_not_set=False))
    if not require_approve:
        LOGGER.debug("[User Registration - Step 3A] moving on to complete registration (no approval required)")
        complete_user_registration(tmp_token, request)
        data = {
            # from the message UI page template, it is possible to see the 'Login' button in the Magpie header
            # user should be able to find its way there to use its registered account
            "message": cleandoc("""
                Your email has been confirmed.

                You can now proceed to the login page to obtain access to resources.
                Please note that you could still need to request further access for some protected content.
                """)
        }
    else:
        LOGGER.debug("[User Registration - Step 3B] moving on to request admin approval")
        request_admin_approval(tmp_token, request)
        data = {
            "message": cleandoc("""
                Your email has been confirmed.

                You will be notified with another email once an administrator reviews and approves your request.
                """)
        }
    data["MAGPIE_SUB_TITLE"] = "User Registration"
    return BaseViews(request).render("magpie.ui.home:templates/message.mako", data)


def request_admin_approval(tmp_token, request):
    # type: (TemporaryToken, Request) -> None
    """
    Sends the email to the administrator to approve or refuse the :term:`Pending User` registration.

    Implements step (3B) of the user registration procedure.

    .. seealso::
        - See :ref:`proc_user_registration` for the procedure step details.
    """
    tmp_user = tmp_token.user
    LOGGER.debug("[User Registration - Step 3B] request admin approval for pending user: [%s]", tmp_user.user_name)
    approve_url = generate_callback_url(TokenOperation.USER_REGISTRATION_ADMIN_APPROVE, request.db, user=tmp_user)
    decline_url = generate_callback_url(TokenOperation.USER_REGISTRATION_ADMIN_DECLINE, request.db, user=tmp_user)
    magpie_url = get_magpie_url(request)
    params = {
        "user": tmp_user,
        "approve_url": approve_url,
        "decline_url": decline_url,
        "pending_url": magpie_url + s.RegisterUserAPI.path.format(user_name=tmp_user.user_name),
        "display_url": magpie_url + "/ui/register/users/" + tmp_user.user_name,
    }
    admin_email = get_constant("MAGPIE_USER_REGISTRATION_APPROVAL_EMAIL_RECIPIENT", request)
    template = get_email_template("MAGPIE_USER_REGISTRATION_APPROVAL_EMAIL_TEMPLATE", request)
    ax.evaluate_call(lambda: send_email(admin_email, request, template, params),
                     fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                     msg_on_fail="Error occurred during user registration when trying to send "
                                 "notification email to administrator for pending user approval.")


def handle_user_registration_admin_decision(tmp_token, request):
    # type: (TemporaryToken, Request) -> Response
    """
    Applies the appropriate operation according to the decision the administrator took for the pending registration.

    - *approved*: Moves to step (5)
    - *declined*: Removes the pending user request.

    Generates the appropriate response that will be displayed to the administrator.

    Implements step (4) of the user registration procedure.

    .. seealso::
        - See :ref:`proc_user_registration` for the procedure step details.
        - :func:`complete_user_registration` for step 5 following approval.
    """
    if tmp_token.operation == TokenOperation.USER_REGISTRATION_ADMIN_APPROVE:
        msg = "Pending user registration was successfully approved."
        complete_user_registration(tmp_token, request)
    elif tmp_token.operation == TokenOperation.USER_REGISTRATION_ADMIN_DECLINE:
        # flush the pending user, this should cascade remove any associated temporary tokens
        ax.evaluate_call(lambda: request.db.delete(tmp_token.user), fallback=lambda: request.db.rollback(),
                         content={"user": uf.format_user(tmp_token.user)},
                         http_error=HTTPInternalServerError, msg_on_fail="Failed deletion of pending user.")
        msg = "Pending user registration was successfully declined. Pending user has been deleted."
    else:
        msg = "Unknown operation received during pending user registration decision by administrator."
        ax.raise_http(HTTPInternalServerError, detail=msg, content=tmp_token.json())
    return BaseViews(request).render("magpie.ui.home:templates/message.mako", {"message": msg})


def complete_user_registration(tmp_token, request):
    # type: (TemporaryToken, Request) -> None
    """
    Completes the successful user registration following any required validation steps.

    Generates the :term:`User` from the :term:`Pending User`.
    Then, sends configured notification emails about successful :term:`User` creation.

    Implements steps (5) and (6) of the user registration procedure.

    .. seealso::
        - See :ref:`proc_user_registration` for the procedure step details.
        - :func:`register_pending_user` for initial steps that started the process.
        - :func:`request_admin_approval` for intermediate steps if approval feature was enabled.
    """
    LOGGER.debug("[User Registration - Step 5] pending user: [%s]", tmp_token.user.user_name)

    # detach pending user from temporary token to avoid db integrity error since it will become invalid after upgrade
    pending_user = tmp_token.user
    tmp_token.user_pending_id = None
    user = pending_user.upgrade(db_session=request.db)
    LOGGER.debug("Pending user upgraded to full user: [%s (%s)]", user.user_name, user.id)

    # notify the user of its successful account validation, approval and creation
    params = {"user": user}
    template = get_email_template("MAGPIE_USER_REGISTRATION_COMPLETED_EMAIL_TEMPLATE", request)
    ax.evaluate_call(lambda: send_email(user.email, request, template, params),
                     fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                     msg_on_fail="Error occurred during user registration when trying to send "
                                 "email to pending user for confirmation of its submitted email.")

    # send other administrative email notification if requested
    notify = asbool(get_constant("MAGPIE_USER_REGISTRATION_NOTIFY_ENABLED", request, default_value=False,
                                 print_missing=True, raise_missing=False, raise_not_set=False))
    if notify:
        LOGGER.debug("[User Registration - Step 6] notify completed registration: [%s]", user.user_name)
        recipient = get_constant("MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_RECIPIENT", request)
        template = get_email_template("MAGPIE_USER_REGISTRATION_NOTIFY_EMAIL_TEMPLATE", request)
        params = {"user": user}
        sent = ax.evaluate_call(lambda: send_email(recipient, request, template, params),
                                fallback=lambda: request.db.rollback(), http_error=HTTPInternalServerError,
                                msg_on_fail="Error occurred during user registration when attempting to "
                                            "send notification email of completed operation.")
        if not sent:
            LOGGER.error("[User Registration - Step 6] error sending email notification (complete registration)")
    LOGGER.debug("[User Registration] completed registration: [%s]", user.user_name)
