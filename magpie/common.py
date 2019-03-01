#!/usr/bin/env python
# -*- coding: utf-8 -*-
from magpie.definitions.pyramid_definitions import Response, HTTPException
from webob.headers import ResponseHeaders, EnvironHeaders
from requests.structures import CaseInsensitiveDict
from distutils.dir_util import mkpath
from six.moves import configparser
from typing import TYPE_CHECKING
import logging
import types
import six
import sys
import os
if TYPE_CHECKING:
    from magpie.definitions.typedefs import (  # noqa: F401
        AnyResponseType, AnyHeadersType, LoggerType, Str, List, Optional, Type, Union
    )

JSON_TYPE = 'application/json'
HTML_TYPE = 'text/html'
PLAIN_TYPE = 'text/plain'
CONTENT_TYPES = [JSON_TYPE, HTML_TYPE, PLAIN_TYPE]


def get_logger(name, level=None):
    """
    Immediately sets the logger level to avoid duplicate log outputs
    from the `root logger` and `this logger` when `level` is `NOTSET`.
    """
    from magpie.constants import MAGPIE_LOG_LEVEL
    logger = logging.getLogger(name)
    logger.setLevel(level or MAGPIE_LOG_LEVEL)
    return logger


def print_log(msg, logger=None, level=logging.INFO):
    if not logger:
        logger = get_logger(__name__)
    all_handlers = logging.root.handlers + logger.handlers
    if not any(isinstance(h, logging.StreamHandler) for h in all_handlers):
        logger.addHandler(logging.StreamHandler(sys.stdout))
    if logger.disabled:
        logger.disabled = False
    logger.log(level, msg)


def raise_log(msg, exception=Exception, logger=None, level=logging.ERROR):
    # type: (Str, Optional[Type[Exception]], Optional[LoggerType], Optional[int]) -> None
    if not logger:
        logger = get_logger(__name__)
    logger.log(level, msg)
    if not hasattr(exception, 'message'):
        exception = Exception
    raise exception(msg)


def bool2str(value):
    return 'true' if value in ['on', 'true', 'True', True] else 'false'


def str2bool(value):
    return True if value in ['on', 'true', 'True', True] else False


def islambda(func):
    return isinstance(func, types.LambdaType) and func.__name__ == (lambda: None).__name__


def isclass(obj):
    """
    Evaluate an object for class type (ie: class definition, not an instance nor any other type).

    :param obj: object to evaluate for class type
    :return: (bool) indicating if `object` is a class
    """
    return isinstance(obj, (type, six.class_types))


# alternative to 'makedirs' with 'exists_ok' parameter only available for python>3.5
def make_dirs(path):
    dir_path = os.path.dirname(path)
    if not os.path.isfile(path) or not os.path.isdir(dir_path):
        for subdir in mkpath(dir_path):
            if not os.path.isdir(subdir):
                os.mkdir(subdir)


def get_settings_from_config_ini(config_ini_path, ini_main_section_name='app:magpie_app'):
    parser = configparser.ConfigParser()
    parser.optionxform = lambda option: option  # preserve case of config (ziggurat requires it for 'User' model)
    parser.read([config_ini_path])
    settings = dict(parser.items(ini_main_section_name))
    return settings


def get_json(response):
    """
    Retrieves the 'JSON' body of a response using the property/callable
    according to the response's implementation.
    """
    if isinstance(response.json, dict):
        return response.json
    return response.json()


def get_header(header_name, header_container, default=None, split=None):
    # type: (Str, AnyHeadersType, Optional[Str], Optional[Union[Str, List[Str]]]) -> Union[Str, None]
    """
    Retrieves ``header_name`` by fuzzy match (independently of upper/lower-case and underscore/dash)
    from various framework implementations of ``Headers``.

    If ``split`` is specified, the matched ``header_name`` is first split with it and the first item is returned.
    This allows to parse complex headers (e.g.: ``text/plain; charset=UTF-8`` to ``text/plain`` with ``split=';'``).

    :param header_name: header to find.
    :param header_container: where to look for `header_name`.
    :param default: value to returned if `header_container` is invalid or `header_name` could not be found.
    :param split: character(s) to use to split the *found* `header_name`.
    """
    def fuzzy_name(name):
        return name.lower().replace('-', '_')

    if header_container is None:
        return default
    headers = header_container
    if isinstance(headers, (ResponseHeaders, EnvironHeaders, CaseInsensitiveDict)):
        headers = dict(headers)
    if isinstance(headers, dict):
        headers = header_container.items()
    header_name = fuzzy_name(header_name)
    for h, v in headers:
        if fuzzy_name(h) == header_name:
            if isinstance(split, six.string_types) and len(split) > 1:
                split = [c for c in split]
            if hasattr(split, '__iter__') and not isinstance(split, six.string_types):
                for s in split:
                    v = v.replace(s, split[0])
                split = split[0]
            return (v.split(split)[0] if split else v).strip()
    return default


def convert_response(response):
    # type: (AnyResponseType) -> Response
    """
    Converts a ``response`` implementation (e.g.: ``requests.Response``)
    to an equivalent ``pyramid.response.Response`` version.
    """
    if isinstance(response, Response):
        return response
    json_body = get_json(response)
    pyramid_response = Response(body=json_body, headers=response.headers)
    if hasattr(response, 'cookies'):
        for cookie in response.cookies:
            pyramid_response.set_cookie(name=cookie.name, value=cookie.value, overwrite=True)
    if isinstance(response, HTTPException):
        # noinspection PyProtectedMember
        for header_name, header_value in response.headers._items:
            if header_name.lower() == 'set-cookie':
                pyramid_response.set_cookie(name=header_name, value=header_value, overwrite=True)
    return pyramid_response
