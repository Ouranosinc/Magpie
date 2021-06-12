#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Magpie helpers for database migration.
"""
import argparse
from typing import TYPE_CHECKING

from magpie.constants import get_constant
from magpie.db import run_database_migration

if TYPE_CHECKING:
    # pylint: disable=W0611,unused-import
    from typing import Any, Optional, Sequence

    from magpie.typedefs import Str


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Run Magpie database migration.")
    parser.add_argument("-c", "--config", "--config-file", "--ini", metavar="CONFIG", dest="config_file",
                        type=str, default=get_constant("MAGPIE_INI_FILE_PATH"),
                        help="Configuration file to employ for database connection settings "
                             "(default: MAGPIE_INI_FILE_PATH='%(default)s)'")
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    return run_database_migration(container={"magpie.ini_file_path": args.config_file})


if __name__ == "__main__":
    main()
