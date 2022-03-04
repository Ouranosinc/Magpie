#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Magpie helpers for service providers registration.
"""
import argparse
from typing import TYPE_CHECKING

from magpie.cli.utils import make_logging_options, setup_logger_from_options
from magpie.constants import get_constant
from magpie.db import get_db_session_from_config_ini
from magpie.register import magpie_register_services_from_config
from magpie.utils import get_logger

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Optional, Sequence

    from magpie.typedefs import Str

LOGGER = get_logger(__name__,
                    message_format="%(asctime)s - %(levelname)s - %(message)s",
                    datetime_format="%d-%b-%y %H:%M:%S", force_stdout=False)


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Register service providers into Magpie and Phoenix.")
    parser.add_argument("-c", "--config-file", metavar="PROVIDERS_CONFIG", dest="providers_config",
                        type=str, default=get_constant("MAGPIE_PROVIDERS_CONFIG_PATH"),
                        help="Configuration file to employ for services registration (default: %(default)s).")
    parser.add_argument("-f", "--force-update", default=False, action="store_true", dest="force_update",
                        help="Enforce update of services URL if conflicting services are found (default: %(default)s).")
    parser.add_argument("-g", "--no-getcapabilities-overwrite", default=False, action="store_true",
                        dest="no_getcapabilities",
                        help="Disable overwriting 'GetCapabilities' permission to allow applicable services that "
                             "support it to become publicly accessible if this permission was missing or already "
                             "exists but was incorrectly defined. Anonymous group would then be given permission for "
                             "'GetCapabilities' to grant public access to the service entrypoint. "
                             "(default: %(default)s)")
    parser.add_argument("-p", "--phoenix-push", default=False, action="store_true", dest="phoenix_push",
                        help="push registered Magpie services to sync in Phoenix (default: %(default)s)")
    parser.add_argument("--db", "--use-db-session", default=False, action="store_true", dest="use_db_session",
                        help="Update registered services using database session configuration instead of API requests. "
                             "Can be combined with --config to specify custom configuration (default: %(default)s).")
    parser.add_argument("--config", "--ini", metavar="CONFIG", dest="ini_config",
                        default=get_constant("MAGPIE_INI_FILE_PATH"),
                        help="Configuration INI file to retrieve database connection settings (default: %(default)s).")
    make_logging_options(parser)
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, args)
    db_session = None
    if args.use_db_session:
        db_session = get_db_session_from_config_ini(args.ini_config)
    return magpie_register_services_from_config(args.providers_config,
                                                push_to_phoenix=args.phoenix_push, force_update=args.force_update,
                                                disable_getcapabilities=args.no_getcapabilities, db_session=db_session)


if __name__ == "__main__":
    main()
