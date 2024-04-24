#!/usr/bin/env python3

"""
Create a private key file used to generate a JSON Web Key.

This file is required when network mode is enabled in order to sign JSON Web Tokens.
"""

import argparse
import os.path
import sys
from typing import TYPE_CHECKING

from magpie.api.management.network.network_utils import pem_files, create_private_key
from magpie.cli.utils import make_logging_options, setup_logger_from_options
from magpie.constants import get_constant
from magpie.utils import get_logger, get_settings_from_config_ini

if TYPE_CHECKING:
    from typing import Optional, Sequence

    from magpie.typedefs import Str

LOGGER = get_logger(__name__,
                    message_format="%(asctime)s - %(levelname)s - %(message)s",
                    datetime_format="%d-%b-%y %H:%M:%S", force_stdout=False)


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Create a private key used to generate a JSON Web Key.")
    parser.add_argument("--config", "--ini", metavar="CONFIG", dest="ini_config",
                        default=get_constant("MAGPIE_INI_FILE_PATH"),
                        help="Configuration INI file to retrieve database connection settings (default: %(default)s).")
    parser.add_argument("--key-file",
                        help="Location to write key file to. Default is to use the first file listed in the "
                             "MAGPIE_NETWORK_PEM_FILES variable.")
    parser.add_argument("--password",
                        help="Password used to encrypt the key file. Default is to not encrypt the key file unless the "
                             "the --key-file argument is not set and there is an associated password in the "
                             "MAGPIE_NETWORK_PEM_PASSWORDS variable.")
    parser.add_argument("--force", action="store_true", help="Recreate the key file if it already exists.")
    make_logging_options(parser)
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> int
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, args)
    settings_container = get_settings_from_config_ini(args.ini_config)

    if args.key_file:
        key_file = args.key_file
    else:
        pem_files_ = pem_files(settings_container)
        if pem_files_:
            key_file = pem_files_[0]
        else:
            LOGGER.error(
                "No network PEM files specified. Either set MAGPIE_NETWORK_PEM_FILES or use the --key-file argument")
            return 1

    if os.path.isfile(key_file) and not args.force:
        LOGGER.warning("File %s already exists. To overwrite this file use the --force option.", key_file)
        return 2

    password = args.password
    if password is not None:
        password = password.encode()

    create_private_key(key_file, password=password, settings_container=settings_container)
    return 0


if __name__ == "__main__":
    sys.exit(main())
