from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPInternalServerError

from magpie.api.exception import evaluate_call
from magpie.api.management.user import user_formats as uf
from magpie.constants import get_constant
from magpie.models import TemporaryToken, TokenOperation

if TYPE_CHECKING:
    from typing import Optional

    from magpie.models import UserPending
    from magpie.typedefs import AnySettingsContainer, JSON


def format_pending_user(user, basic_info=False, dotted=False, container=None):
    # type: (UserPending, bool, bool, Optional[AnySettingsContainer]) -> JSON
    """
    Formats a :term:`Pending User` information into JSON.

    :param user: :term:`Pending User` to be formatted.
    :param basic_info:
        If ``True``, return only sufficient details to identify the :term:`Pending User` registration.
    :param dotted:
        Employ a dot (``.``) instead of underscore (``_``) to separate :term:`Pending User` from its basic information.
    :param container: application settings container used to retrieve more metadata about the :term:`Pending User`.
    """
    def fmt_usr():
        info = uf.format_user(user, basic_info=True, dotted=dotted)
        if basic_info:
            return info
        tmp_tokens = TemporaryToken.by_user(user)
        approval = get_constant("MAGPIE_USER_REGISTRATION_APPROVAL_ENABLED", container,
                                default_value=False, print_missing=True, raise_missing=False, raise_not_set=False)

        # any of those urls can be null if already processed, expired, or not applicable as per configuration
        confirm_url = None
        approve_url = None
        decline_url = None
        if approval:
            approve = tmp_tokens.filter(TemporaryToken.operation == TokenOperation.USER_REGISTRATION_ADMIN_APPROVE)
            approve = approve.first()
            if approve:
                approve_url = approve.url(settings=container)
            decline = tmp_tokens.filter(TemporaryToken.operation == TokenOperation.USER_REGISTRATION_ADMIN_DECLINE)
            decline = decline.first()
            if decline:
                decline_url = decline.url(settings=container)
        confirm = tmp_tokens.filter(TemporaryToken.operation == TokenOperation.USER_REGISTRATION_CONFIRM_EMAIL)
        confirm = confirm.first()
        if confirm:
            confirm_url = confirm.url(settings=container)
        info.update({
            "confirm_url": confirm_url,
            "approve_url": approve_url,
            "decline_url": decline_url,
        })
        return info

    return evaluate_call(
        lambda: fmt_usr(),
        http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format pending user registration.",
        content={"registration": repr(user)}
    )
