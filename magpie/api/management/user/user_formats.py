from pyramid.httpexceptions import HTTPInternalServerError

from magpie.api.exception import evaluate_call
from magpie.constants import get_constant


def format_user(user, group_names=None, basic_info=False, dotted=False):
    """
    Formats a :term:`User` information into JSON.

    :param user: :term:`User` to be formatted.
    :param group_names:
        Override of group name listing to provide as user memberships.
        Retrieve the complete group membership listing from the :paramref:`user` if not provided.
    :param basic_info:
        If ``True``, return only sufficient details to identify the :term:`User`, without any additional group details.
    :param dotted:
        Employ a dot (``.``) instead of underscore (``_``) to separate :term:`User` from its basic information.

    .. seealso::
        :func:`magpie.api.management.group.group_formats.format_group`
    """
    def fmt_usr():
        sep = "." if dotted else "_"
        prefix = "user." if dotted else ""
        user_info = {
            "user{}name".format(sep): str(user.user_name),
            "{}email".format(prefix): str(user.email),
            "{}status".format(prefix): int(user.status)
        }
        if not basic_info:
            grp_names = group_names if group_names else [grp.group_name for grp in user.groups]
            user_info["group_names"] = list(sorted(grp_names))
        if user.user_name != get_constant("MAGPIE_ANONYMOUS_USER"):
            user_info["user{}id".format(sep)] = int(user.id)
        return user_info

    return evaluate_call(
        lambda: fmt_usr(),
        http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format user.",
        content={"user": repr(user)}
    )
