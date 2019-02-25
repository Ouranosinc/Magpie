#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from magpie.definitions.pyramid_definitions import Response, HTTPException
from magpie.definitions.typedefs import Any, AnyHeaders, Str, Optional, Type, Union
from webob.headers import ResponseHeaders, EnvironHeaders
from requests.structures import CaseInsensitiveDict
from distutils.dir_util import mkpath
# noinspection PyProtectedMember
from logging import _loggerClass as LoggerType
import types
import six
from six.moves import configparser
import sys
import os
import logging


def get_logger(name, level=logging.INFO):
    """
    Immediately sets the logger level to avoid duplicate log outputs
    from the `root logger` and `this logger` when `level` is `NOTSET`.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger


LOGGER = get_logger(__name__)


def print_log(msg, logger=LOGGER, level=logging.INFO):
    all_handlers = logging.root.handlers + logger.handlers
    if not any(isinstance(h, logging.StreamHandler) for h in all_handlers):
        logger.addHandler(logging.StreamHandler(sys.stdout))
    if logger.disabled:
        logger.disabled = False
    logger.log(level, msg)


def raise_log(msg, exception=Exception, logger=LOGGER, level=logging.ERROR):
    # type: (Str, Optional[Type[Exception]], Optional[LoggerType], Optional[int]) -> None
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


def get_header(header_name, header_container):
    # type: (Str, AnyHeaders) -> Union[Str, None]
    if header_container is None:
        return None
    headers = header_container
    if isinstance(headers, (ResponseHeaders, EnvironHeaders, CaseInsensitiveDict)):
        headers = dict(headers)
    if isinstance(headers, dict):
        headers = header_container.items()
    header_name = header_name.lower().replace('-', '_')
    for h, v in headers:
        if h.lower().replace('-', '_') == header_name:
            return v
    return None


def convert_response(response):
    # type: (Any) -> Response
    """
    Converts a ``response`` implementation (eg: ``requests.Response``)
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
