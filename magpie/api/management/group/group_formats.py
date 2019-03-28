from magpie.api.api_requests import HTTPInternalServerError
from magpie.api.api_except import evaluate_call


def format_group(group, basic_info=False):
    def fmt_grp(grp, info):
        if info:
            return {
                u'group_name': str(grp.group_name),
                u'group_id': grp.id,
            }
        return {
            u'group_name': str(grp.group_name),
            u'description': str(grp.description),
            u'member_count': grp.member_count,
            u'group_id': grp.id,
            u'user_names': [usr.user_name for usr in grp.users]
        }

    return evaluate_call(
        lambda: fmt_grp(group, basic_info), httpError=HTTPInternalServerError,
        msgOnFail="Failed to format group.", content={u'group': repr(group)}
    )
