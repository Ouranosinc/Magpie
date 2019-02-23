#!/usr/bin/env python
"""Magpie additional typing definitions."""

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from magpie.definitions.sqlalchemy_definitions import Session
    from webob.headers import ResponseHeaders, EnvironHeaders
    from webob.response import Response as WebobResponse
    from webtest.response import TestResponse
    from webtest.app import TestApp
    from requests.cookies import RequestsCookieJar
    from pyramid.response import Response as PyramidResponse
    from pyramid.registry import Registry
    from pyramid.request import Request
    from pyramid.security import Authenticated, Allow, Deny, Everyone
    from pyramid.config import Configurator
    from requests.structures import CaseInsensitiveDict
    from magpie.models import GroupPermission, UserPermission
    # noinspection PyUnresolvedReferences, PyProtectedMember
    from logging import _loggerClass as LoggerType  # noqa: F401
    from tests.interfaces import Base_Magpie_TestCase
    # noinspection PyUnresolvedReferences
    from typing import (  # noqa: F401
        Any, AnyStr as _AnyStr, Callable, Dict, List, Iterable, Optional, Tuple, Type, Union
    )
    import six
    if six.PY2:
        Str = Union[_AnyStr, unicode]
    else:
        Str = _AnyStr
    AnyStr = Str

    SettingValue = Union[Str, int, float, bool, None]
    SettingsType = Dict[Str, SettingValue]
    SettingsContainer = Union[Configurator, Registry, Request, SettingsType]

    ParamsType = Dict[Str, Any]
    CookiesType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    HeadersType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    OptionalHeaderCookiesType = Union[Tuple[None, None], Tuple[HeadersType, CookiesType]]
    AnyHeadersType = Union[HeadersType, ResponseHeaders, EnvironHeaders, CaseInsensitiveDict]
    AnyResponseType = Union[WebobResponse, PyramidResponse, TestResponse]
    CookiesOrSessionType = Union[RequestsCookieJar, Session]

    Number = Union[int, float]
    AnyValue = Union[AnyStr, Number, bool, None]
    AnyKey = Union[AnyStr, int]
    JSON = Dict[AnyKey, Union[AnyValue, Dict[AnyKey, 'JSON'], List['JSON']]]

    UserServicesType = Union[Dict[Str, Dict[Str, Any]], List[Dict[Str, Any]]]
    AccessGrantType = Union[Allow, Deny]
    AccessOwnerType = Union[Authenticated, Everyone, int]
    AccessPermissionType = Str
    AccessControlListType = List[Tuple[AccessGrantType, AccessOwnerType, AccessPermissionType]]
    ResourcePermissionType = Union[GroupPermission, UserPermission]

    TestAppOrUrlType = Union[Str, TestApp]
    AnyMagpieTestType = Union[Type[Base_Magpie_TestCase], Base_Magpie_TestCase, TestAppOrUrlType]
