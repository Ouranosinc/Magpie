# -*- coding: utf-8 -*-
import sys


def includeme(config):
    # import needs to be here, otherwise ImportError happens during setup.py install (modules not yet installed)
    from magpie.api.generic import internal_server_error, unauthorized_or_forbidden, not_found_or_method_not_allowed
    from magpie.constants import get_constant
    from magpie.definitions.pyramid_definitions import NewRequest, EXCVIEW
    from magpie.utils import get_logger

    mod_dir = get_constant("MAGPIE_MODULE_DIR", config)
    logger = get_logger(__name__)
    logger.info("Adding MAGPIE_MODULE_DIR='{}' to path.".format(mod_dir))
    sys.path.insert(0, mod_dir)

    config.add_exception_view(internal_server_error)
    config.add_forbidden_view(unauthorized_or_forbidden)
    config.add_notfound_view(not_found_or_method_not_allowed)

    config.set_default_permission(get_constant("MAGPIE_ADMIN_PERMISSION", config))
    tween_position = EXCVIEW
    if get_constant("MAGPIE_LOG_REQUEST", config):
        config.add_subscriber("magpie.utils.log_request", NewRequest)
    if get_constant("MAGPIE_LOG_EXCEPTION", config):
        config.add_tween("magpie.utils.log_exception_tween", under=tween_position)
        tween_position = "magpie.utils.log_exception_tween"
    config.add_tween("magpie.api.generic.validate_accept_header_tween", under=tween_position)

    config.include("cornice")
    config.include("cornice_swagger")
    config.include("pyramid_chameleon")
    config.include("pyramid_beaker")
    config.include("pyramid_mako")
    config.include("magpie.definitions")
    config.include("magpie.api")
    config.include("magpie.db")
    if get_constant("MAGPIE_UI_ENABLED", config):
        config.include("magpie.ui")
    else:
        logger.warning("Magpie UI not enabled.")
