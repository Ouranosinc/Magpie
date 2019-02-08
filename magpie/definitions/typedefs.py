#!/usr/bin/env python
"""Magpie additional typing definitions."""

# noinspection PyUnresolvedReferences
from typing import Any, AnyStr, Callable, Dict, List, Optional, Tuple, Type, Union, TYPE_CHECKING   # noqa: F401

Str = Union[AnyStr, unicode]

Setting = Union[AnyStr, int, float, bool]
Settings = Dict[AnyStr, Setting]

Cookies = Union[Dict[AnyStr, AnyStr], List[Tuple[AnyStr, AnyStr]]]
Headers = Union[Dict[AnyStr, AnyStr], List[Tuple[AnyStr, AnyStr]]]

JsonField = Union[Str, int, float, bool, Dict['JsonBody'], List['JsonBody']]
JsonBody = Dict[Str, JsonField]

ParamKWArgs = Dict[Str, Any]
