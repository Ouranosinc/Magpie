# -*- coding: utf-8 -*-
import sys


def includeme(config):
    # import needs to be here, otherwise ImportError happens during setup.py install (modules not yet installed)
    from magpie import constants
    sys.path.insert(0, constants.MAGPIE_MODULE_DIR)
    from magpie.common import get_logger
    logger = get_logger(__name__)
    logger.info("Adding MAGPIE_MODULE_DIR='{}' to path.".format(constants.MAGPIE_MODULE_DIR))

    # include magpie components (all the file which define includeme)
    config.include('cornice')
    config.include('cornice_swagger')
    config.include('pyramid_chameleon')
    config.include('pyramid_mako')
    config.include('magpie.definitions')
    config.include('magpie.api')
    config.include('magpie.db')
    config.include('magpie.ui')
