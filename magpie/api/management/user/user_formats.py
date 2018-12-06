from magpie.definitions.pyramid_definitions import HTTPInternalServerError
from magpie.api.api_except import evaluate_call


def format_user(user, group_names=None):
    def fmt_usr(usr, grp_names):
        return {
            u'user_name': str(usr.user_name),
            u'email': str(usr.email),
            u'group_names': sorted(list(grp_names) if grp_names else [grp.group_name for grp in user.groups]),
        }

    return evaluate_call(
        lambda: fmt_usr(user, group_names),
        httpError=HTTPInternalServerError,
        msgOnFail="Failed to format user.",
        content={u'user': repr(user)}
    )
