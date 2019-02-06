# noinspection PyUnresolvedReferences
from typing import Any, AnyStr, Dict, List, Optional, Tuple, Type, Union    # noqa: F401

Setting = Union[AnyStr, int, float, bool]
Settings = Dict[AnyStr, Setting]

Cookies = Union[Dict[AnyStr, AnyStr], List[Tuple[AnyStr, AnyStr]]]
Headers = Union[Dict[AnyStr, AnyStr], List[Tuple[AnyStr, AnyStr]]]

JsonField = Union[AnyStr, int, float, bool, 'JsonBody']
JsonBody = Dict[AnyStr, JsonField]
