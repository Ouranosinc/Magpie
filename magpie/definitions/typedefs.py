#!/usr/bin/env python
"""Magpie additional typing definitions."""

# noinspection PyUnresolvedReferences
from typing import Any, AnyStr, Callable, Dict, List, Optional, Tuple, Type, Union, TYPE_CHECKING   # noqa: F401
from webob.headers import ResponseHeaders, EnvironHeaders
from pyramid.config import Configurator
from pyramid.registry import Registry
from pyramid.request import Request
from requests.structures import CaseInsensitiveDict
import six

if six.PY2:
    Str = Union[AnyStr, unicode]
else:
    Str = AnyStr

Setting = Union[AnyStr, int, float, bool, None]
Settings = Dict[AnyStr, Setting]

SettingsContainer = Union[Configurator, Registry, Request, Settings]

Cookies = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
Headers = Union[Dict[Str, Str], List[Tuple[Str, Str]]]
OptionalHeaderCookies = Union[Tuple[None, None], Tuple[Headers, Cookies]]
AnyHeaders = Union[Headers, ResponseHeaders, EnvironHeaders, CaseInsensitiveDict]

JsonField = Union[Str, int, float, bool, None]
JsonBody = Dict[Str, Union[JsonField, Dict[Str, Any], List[Any]]]

ParamKWArgs = Dict[Str, Any]
