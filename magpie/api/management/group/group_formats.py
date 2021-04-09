import math
from typing import TYPE_CHECKING

from pyramid.httpexceptions import HTTPInternalServerError

from magpie.api.exception import evaluate_call

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Optional

    from sqlalchemy.orm.session import Session

    from magpie.models import Group
    from magpie.typedefs import JSON


def format_group(group, basic_info=False, public_info=False, dotted=False, db_session=None):
    # type: (Group, bool, bool, bool, Optional[Session]) -> JSON
    """
    Obtains the JSON formatted :term:`Group` definition according to field selection flags.

    :param group: Group for which to provide details.
    :param basic_info:
        If ``True``, return only sufficient details to identify the group (useful for routes that refer to a group,
        but that are not requesting it specifically), or return full details (for routes that specifically request
        its information, e.g.: ``GET /groups/{grp}``).
    :param public_info:
        Indicate if the returned details are intended for public information (``True``) or admin-only (``False``).
        Only higher level users should be provided additional details to avoid leaking potentially sensitive parameters.
    :param dotted:
        Employ a dot (``.``) instead of underscore (``_``) to separate :term:`Group` from its basic information.
    :param db_session: Database connection to retrieve additional details (required when ``public_info=False``).
    """
    def fmt_grp():
        sep = "." if dotted else "_"
        info = {"group{}name".format(sep): str(group.group_name)}
        if not public_info:
            info["group{}id".format(sep)] = group.id
        if basic_info:
            return info
        info["description"] = str(group.description) if group.description else None
        if public_info:
            return info
        info["discoverable"] = group.discoverable
        info["priority"] = "max" if group.priority == math.inf else int(group.priority)
        info["member_count"] = group.get_member_count(db_session)
        info["user_names"] = [usr.user_name for usr in group.users]
        return info

    return evaluate_call(
        lambda: fmt_grp(), http_error=HTTPInternalServerError,
        msg_on_fail="Failed to format group.", content={"group": repr(group)}
    )
