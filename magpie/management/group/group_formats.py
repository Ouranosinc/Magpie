from api_requests import *


def format_group(group):
    def fmt_grp(grp):
        return {
            u'group_name': str(grp.group_name),
            u'description': str(grp.description),
            u'member_count': grp.member_count,
            u'group_id': grp.id,
            u'users': grp.users
        }

    return evaluate_call(
        lambda: fmt_grp(group), httpError=HTTPInternalServerError,
        msgOnFail="Failed to format group", content={u'group': repr(group)}
    )
