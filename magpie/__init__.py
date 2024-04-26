# -*- coding: utf-8 -*-
# NOTE:
#   Do not import anything here that is not part of the python standard library.
#   Any external package could still not yet be installed when importing the package
#   to access high-level information such as the metadata (__meta__.py).
from __future__ import unicode_literals

import sys

# FIXME: patch workaround for Python 3.12 issue with vendor-specific 'six.moves'
#   Inspired from https://github.com/dpkp/kafka-python/issues/2401#issuecomment-1760208950
#   Applied here such that anything importing 'magpie' does it first, to avoid patch everywhere importing 'authomatic'.
#   Official fix required (see https://github.com/authomatic/authomatic/issues/233).
if sys.version_info >= (3, 12, 0):
    import six
    sys.modules["authomatic.six.moves"] = six.moves
    sys.modules["authomatic.six.moves.urllib"] = six.moves.urllib
    sys.modules["authomatic.six.moves.urllib.parse"] = six.moves.urllib.parse


def includeme(config):
    # import needs to be here, otherwise ImportError happens during setup.py install (modules not yet installed)
    # pylint: disable=C0415
    from magpie.constants import get_constant
    from magpie.utils import get_logger

    mod_dir = get_constant("MAGPIE_MODULE_DIR", config)
    logger = get_logger(__name__)
    logger.info("Adding MAGPIE_MODULE_DIR='%s' to path.", mod_dir)
    sys.path.insert(0, mod_dir)

    config.include("magpie.api")
    config.include("magpie.db")
    if get_constant("MAGPIE_UI_ENABLED", config):
        config.include("magpie.ui")
    else:
        logger.warning("Magpie UI not enabled.")
