#!/usr/bin/env python
# coding: utf-8

"""
Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations.
"""
import logging

from pyramid.settings import asbool
from pyramid_beaker import set_cache_regions_from_settings

from magpie.api.webhooks import setup_webhooks
from magpie.cli.register_defaults import register_defaults
from magpie.constants import get_constant
from magpie.db import get_db_session_from_config_ini, run_database_migration_when_ready, set_sqlalchemy_log_level
from magpie.register import magpie_register_permissions_from_config, magpie_register_services_from_config
from magpie.security import get_auth_config
from magpie.utils import get_logger, patch_magpie_url, print_log, setup_ziggurat_config

LOGGER = get_logger(__name__)


def main(global_config=None, **settings):  # noqa: F811
    """
    This function returns a Pyramid WSGI application.
    """
    import magpie.constants  # pylint: disable=C0415  # avoid circular import

    # override magpie ini if provided with --paste to gunicorn (or pserve), otherwise use environment variable
    config_env = get_constant("MAGPIE_INI_FILE_PATH", settings, raise_missing=True)
    config_ini = (global_config or {}).get("__file__", config_env)
    if config_ini != config_env:
        magpie.constants.MAGPIE_INI_FILE_PATH = config_ini
        settings["magpie.ini_file_path"] = config_ini

    print_log("Setting up loggers...", LOGGER)
    log_lvl = get_constant("MAGPIE_LOG_LEVEL", settings, "magpie.log_level", default_value="INFO",
                           raise_missing=False, raise_not_set=False, print_missing=True)
    # apply proper value in case it was in ini AND env since up until then, only env was check
    # we want to prioritize the ini definition
    magpie.constants.MAGPIE_LOG_LEVEL = log_lvl
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

    print_log("Validate settings that require explicit definitions...", LOGGER)
    for req_config in ["MAGPIE_SECRET", "MAGPIE_ADMIN_USER", "MAGPIE_ADMIN_PASSWORD"]:
        get_constant(req_config, settings_container=settings, raise_missing=True, raise_not_set=True)

    print_log("Register default users...", LOGGER)
    register_defaults(db_session=db_session, settings=settings)

    print_log("Register service providers...", logger=LOGGER)
    combined_config = get_constant("MAGPIE_CONFIG_PATH", settings, default_value=None,
                                   raise_missing=False, raise_not_set=False, print_missing=True)
    if combined_config:
        print_log("Setting 'MAGPIE_CONFIG_PATH' detected for single file configuration, "
                  "following settings for multi-file configuration will be ignored: "
                  "[MAGPIE_PROVIDERS_CONFIG_PATH, MAGPIE_PERMISSIONS_CONFIG_PATH, MAGPIE_WEBHOOKS_CONFIG_PATH]",
                  logger=LOGGER, level=logging.WARNING)

    push_phoenix = asbool(get_constant("PHOENIX_PUSH", settings, settings_name="phoenix.push", default_value=False,
                                       raise_missing=False, raise_not_set=False, print_missing=True))
    prov_cfg = combined_config or get_constant("MAGPIE_PROVIDERS_CONFIG_PATH", settings, default_value="",
                                               raise_missing=False, raise_not_set=False, print_missing=True)
    magpie_register_services_from_config(prov_cfg, push_to_phoenix=push_phoenix, force_update=True,
                                         disable_getcapabilities=False, db_session=db_session)

    print_log("Register configuration permissions...", LOGGER)
    perm_cfg = combined_config or get_constant("MAGPIE_PERMISSIONS_CONFIG_PATH", settings, default_value="",
                                               raise_missing=False, raise_not_set=False, print_missing=True)
    magpie_register_permissions_from_config(perm_cfg, db_session=db_session)

    print_log("Register webhook configurations...", LOGGER)
    webhook_cfg = combined_config or get_constant("MAGPIE_WEBHOOKS_CONFIG_PATH", settings, default_value="",
                                                  raise_missing=False, raise_not_set=False, print_missing=True)
    setup_webhooks(webhook_cfg, settings)

    print_log("Running configurations setup...", LOGGER)
    patch_magpie_url(settings)

    # avoid cornice conflicting with magpie exception views
    settings["handle_exceptions"] = False

    config = get_auth_config(settings)
    set_cache_regions_from_settings(settings)
    setup_ziggurat_config(config)

    # don't use scan otherwise modules like 'magpie.adapter' are
    # automatically found and cause import errors on missing packages
    print_log("Including Magpie modules...", LOGGER)
    config.include("magpie")
    # config.scan("magpie")

    print_log("Starting Magpie app...", LOGGER)
    wsgi_app = config.make_wsgi_app()
    return wsgi_app


if __name__ == "__main__":
    main()
