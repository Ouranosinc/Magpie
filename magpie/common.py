#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from distutils.dir_util import mkpath
import logging
import types
import six
import os

LOGGER = logging.getLogger(__name__)


def print_log(msg, logger=LOGGER, level=logging.INFO):
    print(msg)
    logger.log(level, msg)


def raise_log(msg, exception=Exception, logger=LOGGER, level=logging.ERROR):
    logger.log(level, msg)
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
