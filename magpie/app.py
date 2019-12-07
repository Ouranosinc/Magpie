#!/usr/bin/env python
# coding: utf-8

"""
Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations.
"""

from magpie.constants import get_constant
from magpie.db import set_sqlalchemy_log_level, get_db_session_from_config_ini, run_database_migration_when_ready
from magpie.definitions.pyramid_definitions import asbool
from magpie.helpers.register_default_users import register_default_users
from magpie.register import (
    magpie_register_services_from_config,
    magpie_register_permissions_from_config,
)
from magpie.security import get_auth_config
from magpie.utils import patch_magpie_url, print_log, get_logger
from pyramid_beaker import set_cache_regions_from_settings
LOGGER = get_logger(__name__)


def main(global_config=None, **settings):  # noqa: F811
    """
    This function returns a Pyramid WSGI application.
    """
    config_ini = get_constant("MAGPIE_INI_FILE_PATH", raise_missing=True)

    print_log("Setting up loggers...", LOGGER)
    log_lvl = get_constant("MAGPIE_LOG_LEVEL", settings, "magpie.log_level", default_value="INFO",
                           raise_missing=False, raise_not_set=False, print_missing=True)
    LOGGER.setLevel(log_lvl)
    sa_settings = set_sqlalchemy_log_level(log_lvl)

    print_log("Looking for db migration requirement...", LOGGER)
    run_database_migration_when_ready(settings)  # cannot pass db session as it might not even exist yet!

    # NOTE:
    #   migration can cause sqlalchemy engine to reset its internal logger level, although it is properly set
    #   to 'echo=False' because engines are re-created as needed... (ie: missing db)
    #   apply configs to re-enforce the logging level of `sqlalchemy.engine.base.Engine`"""
    set_sqlalchemy_log_level(log_lvl)
    # fetch db session here, otherwise, any following db engine connection will re-initialize
    # with a new engine class and logging settings don't get re-evaluated/applied
    db_session = get_db_session_from_config_ini(config_ini, settings_override=sa_settings)

    print_log("Register default users...", LOGGER)
    register_default_users(db_session=db_session, settings=settings)

    print_log("Register configuration providers...", logger=LOGGER)
    push_phoenix = asbool(get_constant("PHOENIX_PUSH", settings, settings_name="magpie.phoenix_push",
                                       raise_missing=False, raise_not_set=False, print_missing=True))
    prov_cfg = get_constant("MAGPIE_PROVIDERS_CONFIG_PATH", default_value="",
                            raise_missing=False, raise_not_set=False, print_missing=True)
    magpie_register_services_from_config(prov_cfg, push_to_phoenix=push_phoenix,
                                         force_update=True, disable_getcapabilities=False, db_session=db_session)

    print_log("Register configuration permissions...", LOGGER)
    perm_cfg = get_constant("MAGPIE_PERMISSIONS_CONFIG_PATH", default_value="",
                            raise_missing=False, raise_not_set=False, print_missing=True)
    magpie_register_permissions_from_config(perm_cfg, db_session=db_session)

    print_log("Running configurations setup...", LOGGER)
    patch_magpie_url(settings)

    # avoid cornice conflicting with magpie exception views
    settings["handle_exceptions"] = False

    config = get_auth_config(settings)
    set_cache_regions_from_settings(settings)

    # don't use scan otherwise modules like 'magpie.adapter' are
    # automatically found and cause import errors on missing packages
    config.include("magpie")
    # config.scan("magpie")

    print_log("Starting Magpie app...", LOGGER)
    wsgi_app = config.make_wsgi_app()
    return wsgi_app


if __name__ == "__main__":
    main()
