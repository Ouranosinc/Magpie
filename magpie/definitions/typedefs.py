#!/usr/bin/env python
"""Magpie additional typing definitions."""

# noinspection PyUnresolvedReferences
from typing import (  # noqa: F401
    Any, AnyStr, Callable, Dict, List, Iterable, Optional, Tuple, Type, Union, TYPE_CHECKING
)
if TYPE_CHECKING:
    from webob.headers import ResponseHeaders, EnvironHeaders
    from webob.response import Response as WebobResponse
    from webtest.response import TestResponse
    from webtest.app import TestApp
    from pyramid.response import Response as PyramidResponse
    from pyramid.registry import Registry
    from pyramid.request import Request
    from pyramid.config import Configurator
    from requests.structures import CaseInsensitiveDict
    # noinspection PyUnresolvedReferences, PyProtectedMember
    from logging import _loggerClass as LoggerType  # noqa: F401
    import six

    if six.PY2:
        Str = Union[AnyStr, unicode]
    else:
        Str = AnyStr

    SettingValue = Union[Str, int, float, bool, None]
    SettingsType = Dict[Str, SettingValue]

    SettingsContainer = Union[Configurator, Registry, Request, SettingsType]

    CookiesType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    HeadersType = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
    OptionalHeaderCookiesType = Union[Tuple[None, None], Tuple[HeadersType, CookiesType]]
    AnyHeadersType = Union[HeadersType, ResponseHeaders, EnvironHeaders, CaseInsensitiveDict]
    AnyResponseType = Union[WebobResponse, PyramidResponse, TestResponse]

    JsonField = Union[Str, int, float, bool, None]
    JsonBody = Dict[Str, Union[JsonField, Dict[Str, Any], List[Any]]]

    ParamKWArgs = Dict[Str, Any]

    UserServicesTypes = Union[Dict[Str, Dict[Str, Any]], List[Dict[Str, Any]]]

    TestAppOrUrlType = Union[Str, TestApp]
