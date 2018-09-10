# -*- coding: utf-8 -*-
import logging
import sys
LOGGER = logging.getLogger(__name__)


def includeme(config):
    # import needs to be here, otherwise ImportError happens during setup.py install (modules not yet installed)
    from magpie import constants
    LOGGER.info("Adding MAGPIE_MODULE_DIR='{}' to path.".format(constants.MAGPIE_MODULE_DIR))
    sys.path.insert(0, constants.MAGPIE_MODULE_DIR)

    # include magpie components (all the file which define includeme)
    config.include('cornice')
    config.include('cornice_swagger')
    config.include('pyramid_chameleon')
    config.include('pyramid_mako')
    config.include('magpie.definitions')
    config.include('magpie.api')
    config.include('magpie.db')
    config.include('magpie.ui')
