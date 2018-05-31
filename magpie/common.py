from distutils.dir_util import mkpath
import logging
import os

LOGGER = logging.getLogger(__name__)


def print_log(msg):
    print(msg)
    LOGGER.debug(msg)


def raise_log(msg, exception=Exception):
    LOGGER.debug(msg)
    raise exception(msg)


def bool2str(value):
    return 'true' if value in ['on', 'true', 'True', True] else 'false'


def str2bool(value):
    return True if value in ['on', 'true', 'True', True] else False


# alternative to 'makedirs' with 'exists_ok' parameter only available for python>3.5
def make_dirs(path):
    dir_path = os.path.dirname(path)
    if not os.path.isfile(path) or not os.path.isdir(dir_path):
        for subdir in mkpath(dir_path):
            if not os.path.isdir(subdir):
                os.mkdir(subdir)
