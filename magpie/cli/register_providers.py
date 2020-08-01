#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Magpie helpers for service providers registration.
"""
import argparse
from typing import TYPE_CHECKING

from magpie.constants import MAGPIE_INI_FILE_PATH, MAGPIE_PROVIDERS_CONFIG_PATH
from magpie.db import get_db_session_from_config_ini
from magpie.register import magpie_register_services_from_config

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, AnyStr, Optional, Sequence  # noqa: F401


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Register service providers into Magpie and Phoenix")
    parser.add_argument("-c", "--config-file", metavar="config_file", dest="config_file",
                        type=str, default=MAGPIE_PROVIDERS_CONFIG_PATH,
                        help="configuration file to employ for services registration (default: %(default)s)")
    parser.add_argument("-f", "--force-update", default=False, action="store_true", dest="force_update",
                        help="enforce update of services URL if conflicting services are found (default: %(default)s)")
    parser.add_argument("-g", "--no-getcapabilities-overwrite", default=False, action="store_true",
                        dest="no_getcapabilities",
                        help="disable overwriting 'GetCapabilities' permissions to applicable services when they "
                             "already exist, ie: when conflicts occur during service creation (default: %(default)s)")
    parser.add_argument("-p", "--phoenix-push", default=False, action="store_true", dest="phoenix_push",
                        help="push registered Magpie services to sync in Phoenix (default: %(default)s)")
    parser.add_argument("-d", "--use-db-session", default=False, action="store_true", dest="use_db_session",
                        help="update registered services using db session config instead of API (default: %(default)s)")
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[AnyStr]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    db_session = None
    if args.use_db_session:
        db_session = get_db_session_from_config_ini(MAGPIE_INI_FILE_PATH)
    return magpie_register_services_from_config(args.config_file,
                                                push_to_phoenix=args.phoenix_push, force_update=args.force_update,
                                                disable_getcapabilities=args.no_getcapabilities, db_session=db_session)


if __name__ == "__main__":
    main()
