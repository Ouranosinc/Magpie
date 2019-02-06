#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from magpie.definitions.pyramid_definitions import Response, HTTPException
from magpie.definitions.typedefs import Any
from distutils.dir_util import mkpath
from typing import AnyStr, Optional, Type
# noinspection PyProtectedMember
from logging import _loggerClass as LoggerType
# noinspection PyCompatibility
import configparser
import logging
import types
import six
import os

LOGGER = logging.getLogger(__name__)


def print_log(msg, logger=LOGGER, level=logging.INFO):
    print(msg)
    logger.log(level, msg)


def raise_log(msg, exception=Exception, logger=LOGGER, level=logging.ERROR):
    # type: (AnyStr, Optional[Type[Exception]], Optional[LoggerType], Optional[int]) -> None
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
