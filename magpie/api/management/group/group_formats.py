from typing import TYPE_CHECKING
from pyramid.httpexceptions import HTTPInternalServerError

from magpie.api.exception import evaluate_call

if TYPE_CHECKING:
    from magpie.typedefs import JSON, Optional  # noqa: F401
    from sqlalchemy.orm.session import Session
    from magpie.models import Group


def format_group(group, basic_info=False, db_session=None):
    # type: (Group, bool, Optional[Session]) -> JSON
    def fmt_grp(grp, info):
        if info:
            return {
                u"group_name": str(grp.group_name),
                u"group_id": grp.id,
            }
        return {
            u"group_name": str(grp.group_name),
            u"description": str(grp.description),
            u"member_count": grp.get_member_count(db_session),
            u"group_id": grp.id,
            u"user_names": [usr.user_name for usr in grp.users]
        }

    return evaluate_call(
        lambda: fmt_grp(group, basic_info), http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format group.", content={u"group": repr(group)}
    )
