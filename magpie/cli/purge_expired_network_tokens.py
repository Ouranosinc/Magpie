#!/usr/bin/env python3

"""
Removes expired network tokens from the database.

This ensures that the network_tokens table doesn't fill up with expired tokens.
Both an expired token and a non-existent token behave the same from an access perspective (user is denied) so
it is safe to automatically remove all expired tokens.
"""

import argparse
from typing import TYPE_CHECKING

import transaction

from magpie import models
from magpie.cli.utils import make_logging_options, setup_logger_from_options
from magpie.constants import get_constant
from magpie.db import get_db_session_from_config_ini
from magpie.utils import get_logger, raise_log, print_log

if TYPE_CHECKING:
    from typing import Optional, Sequence
    from magpie.typedefs import Str

LOGGER = get_logger(__name__,
                    message_format="%(asctime)s - %(levelname)s - %(message)s",
                    datetime_format="%d-%b-%y %H:%M:%S", force_stdout=False)


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Delete all expired network tokens.")
    parser.add_argument("--config", "--ini", metavar="CONFIG", dest="ini_config",
                        default=get_constant("MAGPIE_INI_FILE_PATH"),
                        help="Configuration INI file to retrieve database connection settings (default: %(default)s).")
    make_logging_options(parser)
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> None
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, args)
    db_session = get_db_session_from_config_ini(args.ini_config)
    deleted = models.NetworkToken.get_expired(db_session).delete()
    try:
        transaction.commit()
        db_session.close()
    except Exception as exc:  # noqa: W0703 # nosec: B110 # pragma: no cover
        db_session.rollback()
        raise_log("Failed to delete expired network tokens", exception=type(exc), logger=LOGGER)
    else:
        if deleted:
            print_log("{} expired network tokens deleted".format(deleted), logger=LOGGER)
        else:
            print_log("No expired network tokens found", logger=LOGGER)


if __name__ == "__main__":
    main()
