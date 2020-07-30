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
    """Obtains the JSON formatted group definition according to field selection flags."""
    def fmt_grp(grp, is_basic, is_public):
        info = {"group_name": str(grp.group_name)}
        if is_basic:
            info["group_id"] = grp.id
            return info
        info["description"] = str(grp.description) if grp.description else None
        if is_public:
            return info
        info["discoverable"] = grp.discoverable
        info["member_count"] = grp.get_member_count(db_session)
        info["user_names"] = [usr.user_name for usr in grp.users]
        return info

    return evaluate_call(
        lambda: fmt_grp(group, basic_info, public_info), http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format group.", content={"group": repr(group)}
    )
