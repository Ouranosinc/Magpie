from pyramid.httpexceptions import HTTPInternalServerError

from magpie.api.exception import evaluate_call
from magpie.constants import get_constant


def format_user(user, group_names=None):
    def fmt_usr(usr, grp_names):
        user_info = {
            u"user_name": str(usr.user_name),
            u"email": str(usr.email),
            u"group_names": sorted(list(grp_names) if grp_names else [grp.group_name for grp in user.groups]),
        }
        if user.user_name != get_constant("MAGPIE_ANONYMOUS_USER"):
            user_info[u"user_id"] = int(user.id)
        return user_info

    return evaluate_call(
        lambda: fmt_usr(user, group_names),
        http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format user.",
        content={u"user": repr(user)}
    )
