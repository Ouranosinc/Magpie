#!/usr/bin/env python
"""
Magpie additional typing definitions.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import (                                                                        # noqa: F401,W0212
        Any, AnyStr as _AnyStr, Callable, Dict, List, Iterable, Optional, Tuple, Type, Union    # noqa: F401,W0212
    )
    from sqlalchemy.orm.session import Session
    from magpie import models
    from magpie.permissions import Permission
    from webob.headers import ResponseHeaders, EnvironHeaders
    from webob.response import Response as WebobResponse
    from webtest.response import TestResponse
    from requests.cookies import RequestsCookieJar
    from pyramid.httpexceptions import HTTPException
    from pyramid.response import Response as PyramidResponse
    from pyramid.registry import Registry
    from pyramid.request import Request
    from pyramid.config import Configurator
    from requests.structures import CaseInsensitiveDict
    from logging import Logger as LoggerType  # noqa: F401
    import six

    # pylint: disable=W0611,unused-import  # following definitions provided to be employed elsewhere in the code

    if six.PY2:
        # pylint: disable=E0602,undefined-variable  # unicode not recognized by python 3
        Str = Union[_AnyStr, unicode]  # noqa: E0602,F405,F821
    else:
        Str = _AnyStr
    AnyStr = Str    # pylint: disable=C0103,invalid-name

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
    ResourcePermissionMap = Dict[int, List[Str]]  # raw mapping of permission-names applied per resource ID

    UserServicesType = Union[Dict[Str, Dict[Str, Any]], List[Dict[Str, Any]]]
    ServiceOrResourceType = Union[models.Service, models.Resource]
    ResourcePermissionType = Union[models.GroupPermission, models.UserPermission]
    AnyPermissionType = Union[Permission, ResourcePermissionType, Str]
    AnyAccessPrincipalType = Union[Str, Iterable[Str]]
    AccessControlListType = List[Union[Tuple[Str, Str, Str], Str]]
