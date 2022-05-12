#!/usr/bin/env python
"""
Magpie additional typing definitions.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import math
    import typing
    from typing import Any, AnyStr, Collection, Dict, Iterable, List, Optional, Tuple, Type, Union

    import six
    from pyramid.config import Configurator
    from pyramid.httpexceptions import HTTPException
    from pyramid.registry import Registry
    from pyramid.request import Request as PyramidRequest
    from pyramid.response import Response as PyramidResponse
    from requests.cookies import RequestsCookieJar
    from requests.models import Request as RequestsRequest
    from requests.structures import CaseInsensitiveDict
    from sqlalchemy.orm.session import Session
    from webob.headers import EnvironHeaders, ResponseHeaders
    from webob.request import Request as WebobRequest
    from webob.response import Response as WebobResponse
    from webtest.app import TestRequest
    from webtest.response import TestResponse
    from ziggurat_foundations.permissions import PermissionTuple  # noqa

    from magpie import models
    from magpie.api.webhooks import WEBHOOK_TEMPLATE_PARAMS, WebhookAction, WebhookActionNames
    from magpie.permissions import Permission, PermissionSet

    if hasattr(typing, "TypeAlias"):
        from typing import TypeAlias  # pylint: disable=E0611,no-name-in-module  # Python >= 3.10
    else:
        from typing_extensions import TypeAlias
    if hasattr(typing, "TypedDict"):
        from typing import TypedDict  # pylint: disable=E0611,no-name-in-module
    else:
        from typing_extensions import TypedDict  # noqa
    if hasattr(typing, "Literal"):
        from typing import Literal  # pylint: disable=E0611,no-name-in-module
    else:
        from typing_extensions import Literal  # noqa

    # pylint: disable=W0611,unused-import  # following definitions provided to be employed elsewhere in the code

    if six.PY2:
        # pylint: disable=E0602,undefined-variable  # unicode not recognized by python 3
        Str = Union[AnyStr, unicode]  # noqa: E0602,F405,F821
    else:
        Str = str

    Number = Union[int, float]
    SettingValue = Union[Str, Number, bool, None]
    SettingsType = Dict[Str, SettingValue]
    AnySettingsContainer = Union[Configurator, Registry, PyramidRequest, PyramidResponse, SettingsType]

    ParamsType = Dict[Str, Any]
    CookiesType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    HeadersType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    AnyHeadersType = Union[HeadersType, ResponseHeaders, EnvironHeaders, CaseInsensitiveDict]
    AnyCookiesType = Union[CookiesType, RequestsCookieJar]
    AnyRequestType = Union[WebobRequest, PyramidRequest, RequestsRequest, TestRequest]
    AnyResponseType = Union[WebobResponse, PyramidResponse, HTTPException, TestResponse]
    CookiesOrSessionType = Union[RequestsCookieJar, Session]

    AnyKey = Union[Str, int]
    AnyValue = Union[Str, Number, bool, None]
    _JSONType = "JSON"  # type: TypeAlias   # pylint: disable=C0103
    BaseJSON = Union[AnyValue, List[_JSONType], Dict[AnyKey, _JSONType]]
    JSON = Union[Dict[Str, Union[_JSONType]], List[_JSONType]]

    GroupPriority = Union[int, Type[math.inf]]
    UserServicesType = Union[Dict[Str, Dict[Str, Any]], List[Dict[Str, Any]]]
    ServiceOrResourceType = Union[models.Service, models.Resource]
    PermissionDict = TypedDict("PermissionDict", {
        "name": Str,
        "access": Optional[Str],
        "scope": Optional[Str],
        "type": Optional[Str],
        "reason": Optional[Str]
    }, total=False)
    # recursive nodes structure employed by functions for listing children resources hierarchy
    # {<res-id>: {"node": <res>, "children": {<res-id>: ... }}
    NestedResourceNodes = Dict[int, "ResourceNode"]
    ResourceNode = TypedDict("ResourceNode", {
        "node": ServiceOrResourceType,
        "children": NestedResourceNodes
    }, total=True)
    ResourcePermissionMap = Dict[int, List[PermissionSet]]  # raw mapping of permission-names applied per resource ID
    NestingKeyType = Literal["children", "parent"]

    AnyZigguratPermissionType = Union[
        models.GroupPermission,
        models.UserPermission,
        models.GroupResourcePermission,
        models.UserResourcePermission,
        PermissionTuple,
    ]
    AnyPermissionType = Union[Permission, PermissionSet, PermissionDict, AnyZigguratPermissionType, Str]
    ResolvablePermissionType = Union[PermissionSet, AnyZigguratPermissionType]
    AnyAccessPrincipalType = Union[Str, Iterable[Str]]
    AccessControlEntryType = Union[Tuple[Str, Str, Str], Str]
    AccessControlListType = List[AccessControlEntryType]

    TargetResourceRequested = Tuple[ServiceOrResourceType, bool]
    MultiResourceRequested = Union[None, TargetResourceRequested, List[TargetResourceRequested]]
    PermissionRequested = Optional[Union[Permission, Collection[Permission]]]
    ResourceTypePermissions = Dict[Type[models.Resource], List[Permission]]

    AnyRequestMethod = Literal[
        "HEAD", "GET", "POST", "PUT", "PATCH", "DELETE",
        "head", "get", "post", "put", "patch", "delete",
        "*"
    ]

    # note:
    #   For all following items 'Settings' suffix refer to loaded definitions AFTER resolution.
    #   When 'Config' suffix is used, it instead refers to raw definitions BEFORE resolution.

    WebhookPayload = Union[JSON, Str]
    # items that are substituted dynamically in the payload during webhook handling (eg: {{user.name}})
    WebhookTemplateParameters = TypedDict("WebhookTemplateParameters", {
        param: AnyValue for param in WEBHOOK_TEMPLATE_PARAMS
    })
    WebhookConfigItem = TypedDict("WebhookConfigItem", {
        "name": Str,
        "action": WebhookActionNames,
        "method": AnyRequestMethod,
        "url": Str,
        "format": Str,
        "payload": WebhookPayload
    }, total=False)

    # registered configurations
    PermissionAction = Literal["create", "remove"]
    PermissionConfigItem = TypedDict("PermissionConfigItem", {
        "service": Str,
        "resource": Optional[Str],
        "type": Optional[Str],
        "user": Optional[Str],
        "group": Optional[Str],
        "permission": Union[Str, PermissionDict],
        "action": Optional[PermissionAction],
    }, total=False)
    GroupConfigItem = TypedDict("GroupConfigItem", {
        "name": Str,
        "description": Optional[Str],
        "discoverable": bool,  # must use 'asbool' since technically a bool-like string from config
    }, total=False)
    UserConfigItem = TypedDict("UserConfigItem", {
        "username": Str,
        "password": Optional[Str],
        "email": Optional[Str],
        "group": Optional[Str],
    }, total=False)
    ServiceHookType = Literal["request", "response"]
    ServiceHookConfigItem = TypedDict("ServiceHookConfigItem", {
        "type": ServiceHookType,
        "path": str,
        "query": Optional[str],
        "method": AnyRequestMethod,
        "target": str
    }, total=True)
    # generic 'configuration' field under a service that supports it
    ServiceConfiguration = Dict[Str, Union[Str, List[JSON], JSON]]
    ServiceConfigItem = TypedDict("ServiceConfigItem", {
        "url": Str,
        "title": Str,
        "type": Str,
        "sync_type": Optional[Str],
        # must use 'asbool' since technically a bool-like string from config
        "public": bool,
        "c4i": bool,
        "configuration": Optional[ServiceConfiguration],
        "hooks": Optional[List[ServiceHookConfigItem]]
    })

    # individual sections directly loaded from config files (BEFORE resolution)
    ServicesConfig = Dict[Str, ServiceConfigItem]  # only section already formatted the same way as resolved settings
    PermissionsConfig = List[PermissionConfigItem]
    GroupsConfig = List[GroupConfigItem]
    UsersConfig = List[UserConfigItem]
    WebhooksConfig = List[WebhookConfigItem]

    # when loaded from multiple distinct configuration files, but fetching only a specific section
    # they are never mixed together in this case, so use distinct list per section
    MultiConfigs = Union[  # see as 'OneOf' below list
        List[ServicesConfig],
        List[PermissionsConfig],
        List[UsersConfig],
        List[GroupsConfig],
        List[WebhooksConfig],
    ]

    # combined configuration of respective sections above all within the same file (config.yml)
    CombinedConfig = TypedDict("CombinedConfig", {
        "providers": Optional[ServicesConfig],
        "permissions": Optional[PermissionsConfig],
        "users": Optional[UsersConfig],
        "groups": Optional[GroupsConfig],
        "webhooks": Optional[WebhooksConfig],
    }, total=False)

    # mappings after loading of multiple files for relevant sections (AFTER resolution)
    PermissionsSettings = Dict[Str, PermissionConfigItem]
    ServicesSettings = Dict[Str, ServiceConfigItem]
    GroupsSettings = Dict[Str, GroupConfigItem]
    UsersSettings = Dict[Str, UserConfigItem]
    WebhookSettings = Dict[WebhookAction, List[WebhookConfigItem]]  # many webhooks aggregated by action
    AnyResolvedSettings = Union[PermissionsSettings, ServicesSettings, GroupsSettings, UsersSettings, WebhookSettings]
