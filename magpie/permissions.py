from enum import Enum


class Permission(Enum):
    # file/dir permissions
    READ = u'read'
    READ_MATCH = u'read-match'
    WRITE = u'write'
    WRITE_MATCH = u'write-match'
    ACCESS = u'access'
    # WPS permissions
    GET_CAPABILITIES = u'getcapabilities'
    GET_MAP = u'getmap'
    GET_FEATURE_INFO = u'getfeatureinfo'
    GET_LEGEND_GRAPHIC = u'getlegendgraphic'
    GET_METADATA = u'getmetadata'
    GET_FEATURE = u'getfeature'
    DESCRIBE_FEATURE_TYPE = u'describefeaturetype'
    DESCRIBE_PROCESS = u'describeprocess'
    EXECUTE = u'execute'
    LOCK_FEATURE = u'lockfeature'
    TRANSACTION = u'transaction'
