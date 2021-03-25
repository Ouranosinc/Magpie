#!/usr/bin/env python
"""
Magpie additional typing definitions.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import math
    import typing
    from typing import Any, AnyStr, Dict, Iterable, List, Optional, Tuple, Type, Union

    import six
    from pyramid.config import Configurator
    from pyramid.httpexceptions import HTTPException
    from pyramid.registry import Registry
    from pyramid.request import Request
    from pyramid.response import Response as PyramidResponse
    from requests.cookies import RequestsCookieJar
    from requests.structures import CaseInsensitiveDict
    from sqlalchemy.orm.session import Session
    from webob.headers import EnvironHeaders, ResponseHeaders
    from webob.response import Response as WebobResponse
    from webtest.response import TestResponse
    from ziggurat_foundations.permissions import PermissionTuple  # noqa

    from magpie import models
    from magpie.permissions import Permission, PermissionSet

    if hasattr(typing, "TypedDict"):
        from typing import TypedDict  # pylint: disable=E0611,no-name-in-module
    else:
        from typing_extensions import TypedDict  # noqa

    # pylint: disable=W0611,unused-import  # following definitions provided to be employed elsewhere in the code

    if six.PY2:
        # pylint: disable=E0602,undefined-variable  # unicode not recognized by python 3
        Str = Union[AnyStr, unicode]  # noqa: E0602,F405,F821
    else:
        Str = str

    Number = Union[int, float]
    SettingValue = Union[Str, Number, bool, None]
    SettingsType = Dict[Str, SettingValue]
    AnySettingsContainer = Union[Configurator, Registry, Request, SettingsType]

    ParamsType = Dict[Str, Any]
    CookiesType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    HeadersType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    AnyHeadersType = Union[HeadersType, ResponseHeaders, EnvironHeaders, CaseInsensitiveDict]
    AnyCookiesType = Union[CookiesType, RequestsCookieJar]
    AnyResponseType = Union[WebobResponse, PyramidResponse, HTTPException, TestResponse]
    CookiesOrSessionType = Union[RequestsCookieJar, Session]

    AnyKey = Union[Str, int]
    AnyValue = Union[Str, Number, bool, None]
    BaseJSON = Union[AnyValue, List["BaseJSON"], Dict[AnyKey, "BaseJSON"]]
    JSON = Union[Dict[AnyKey, Union[BaseJSON, "JSON"]], List[BaseJSON]]

    # recursive nodes structure employed by functions for listing children resources hierarchy
    # {<res-id>: {"node": <res>, "children": {<res-id>: ... }}
    ChildrenResourceNodes = Dict[int, Dict[Str, Union[models.Resource, "ChildrenResourceNodes"]]]
    ResourcePermissionMap = Dict[int, List[PermissionSet]]  # raw mapping of permission-names applied per resource ID

    GroupPriority = Union[int, Type[math.inf]]
    UserServicesType = Union[Dict[Str, Dict[Str, Any]], List[Dict[Str, Any]]]
    ServiceOrResourceType = Union[models.Service, models.Resource]
    PermissionDict = TypedDict("PermissionDict",
                               {"name": Str, "access": Optional[Str], "scope": Optional[Str],
                                "type": Optional[Str], "reason": Optional[Str]}, total=False)
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

    # registered configurations
    ConfigItem = Dict[Str, JSON]
    ConfigList = List[ConfigItem]
    ConfigDict = Dict[Str, Union[Str, ConfigItem, ConfigList, JSON]]
