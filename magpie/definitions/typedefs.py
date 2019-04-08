#!/usr/bin/env python
"""Magpie additional typing definitions."""

# noinspection PyUnresolvedReferences
from typing import (  # noqa: F401
    Any, AnyStr as _AnyStr, Callable, Dict, List, Iterable, Optional, Tuple, Type, Union, TYPE_CHECKING
)
if TYPE_CHECKING:
    from magpie.definitions.sqlalchemy_definitions import Session
    from magpie.models import GroupPermission, UserPermission
    from webob.headers import ResponseHeaders, EnvironHeaders
    from webob.response import Response as WebobResponse
    from webtest.response import TestResponse
    from webtest.app import TestApp
    from requests.cookies import RequestsCookieJar
    from pyramid.response import Response as PyramidResponse
    from pyramid.registry import Registry
    from pyramid.request import Request
    from pyramid.config import Configurator
    from requests.structures import CaseInsensitiveDict
    # noinspection PyUnresolvedReferences, PyProtectedMember
    from logging import _loggerClass as LoggerType  # noqa: F401
    from tests.interfaces import Base_Magpie_TestCase
    import six

    if six.PY2:
        Str = Union[_AnyStr, unicode]
    else:
        Str = _AnyStr
    AnyStr = Str

    Number = Union[int, float]
    SettingValue = Union[Str, Number, bool, None]
    SettingsType = Dict[Str, SettingValue]
    SettingsContainer = Union[Configurator, Registry, Request, SettingsType]

    ParamsType = Dict[Str, Any]
    CookiesType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    HeadersType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    OptionalHeaderCookiesType = Union[Tuple[None, None], Tuple[HeadersType, CookiesType]]
    AnyHeadersType = Union[HeadersType, ResponseHeaders, EnvironHeaders, CaseInsensitiveDict]
    AnyResponseType = Union[WebobResponse, PyramidResponse, TestResponse]
    CookiesOrSessionType = Union[RequestsCookieJar, Session]

    AnyKey = Union[Str, int]
    AnyValue = Union[Str, Number, bool, None]
    BaseJSON = Union[AnyValue, List["BaseJSON"], Dict[AnyKey, "BaseJSON"]]
    JSON = Dict[AnyKey, BaseJSON]

    UserServicesType = Union[Dict[Str, Dict[Str, Any]], List[Dict[Str, Any]]]
    ResourcePermissionType = Union[GroupPermission, UserPermission]

    TestAppOrUrlType = Union[Str, TestApp]
    AnyMagpieTestType = Union[Type[Base_Magpie_TestCase], Base_Magpie_TestCase, TestAppOrUrlType]
