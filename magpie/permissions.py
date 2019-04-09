from magpie.utils import ExtendedEnumMeta
from six import with_metaclass
from enum import Enum
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.typedefs import Iterable, List, Str, ResourcePermissionType, Union  # noqa: F401


class Permission(with_metaclass(ExtendedEnumMeta, Enum)):
    # file/dir permissions
    READ = u"read"
    READ_MATCH = u"read-match"
    WRITE = u"write"
    WRITE_MATCH = u"write-match"
    ACCESS = u"access"
    # WPS permissions
    GET_CAPABILITIES = u"getcapabilities"
    GET_MAP = u"getmap"
    GET_FEATURE_INFO = u"getfeatureinfo"
    GET_LEGEND_GRAPHIC = u"getlegendgraphic"
    GET_METADATA = u"getmetadata"
    GET_FEATURE = u"getfeature"
    DESCRIBE_FEATURE_TYPE = u"describefeaturetype"
    DESCRIBE_PROCESS = u"describeprocess"
    EXECUTE = u"execute"
    LOCK_FEATURE = u"lockfeature"
    TRANSACTION = u"transaction"


def format_permissions(permissions):
    # type: (Iterable[Union[Permission, ResourcePermissionType, Str]]) -> List[Str]
    """
    Obtains the formatted permission representation after validation that it is a member of ``Permission`` enum.
    The returned list is sorted alphabetically and cleaned of any duplicate entries.
    """
    perms = []
    for p in permissions:
        p_valid = p if p in Permission else Permission.get(getattr(p, "perm_name", None) or p)
        if p_valid:
            perms.append(p_valid)
    return list(sorted(set([p.value for p in perms])))  # remove any duplicates entries
