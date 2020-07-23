from typing import TYPE_CHECKING
from pyramid.httpexceptions import HTTPInternalServerError

from magpie.api.exception import evaluate_call

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from magpie.typedefs import JSON, Optional  # noqa: F401
    from sqlalchemy.orm.session import Session
    from magpie.models import Group


def format_group(group, basic_info=False, public_info=False, db_session=None):
    # type: (Group, bool, bool, Optional[Session]) -> JSON
    def fmt_grp(grp, is_basic, is_public):
        info = {
            u"group_name": str(grp.group_name),
            u"group_id": grp.id,
        }
        if is_basic:
            return info
        info[u"description"] = str(grp.description) if grp.description else None
        if is_public:
            return info
        info[u"member_count"] = grp.get_member_count(db_session)
        info[u"user_names"] = [usr.user_name for usr in grp.users]
        return info

    return evaluate_call(
        lambda: fmt_grp(group, basic_info, public_info), http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format group.", content={u"group": repr(group)}
    )
