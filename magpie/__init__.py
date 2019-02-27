# -*- coding: utf-8 -*-
import sys


def includeme(config):
    # import needs to be here, otherwise ImportError happens during setup.py install (modules not yet installed)
    from magpie.definitions.pyramid_definitions import NewRequest, EXCVIEW
    from magpie.constants import get_constant
    from magpie.common import get_logger

    mod_dir = get_constant('MAGPIE_MODULE_DIR')
    logger = get_logger(__name__)
    logger.info("Adding MAGPIE_MODULE_DIR='{}' to path.".format(mod_dir))
    sys.path.insert(0, mod_dir)

    config.set_default_permission(get_constant('MAGPIE_ADMIN_PERMISSION'))
    config.add_subscriber('magpie.utils.proxy_url', NewRequest)
    config.add_subscriber('magpie.utils.log_request', NewRequest)
    config.add_tween('magpie.utils.log_exception', under=EXCVIEW)

    # include magpie components (all the file which define includeme)
    config.include('cornice')
    config.include('cornice_swagger')
    config.include('pyramid_chameleon')
    config.include('pyramid_mako')
    config.include('magpie.definitions')
    config.include('magpie.api')
    config.include('magpie.db')
    config.include('magpie.ui')
