#!/usr/bin/env python3

"""
Removes expired network tokens from the database.

This ensures that the network_tokens table doesn't fill up with expired tokens.
Both an expired token and a non-existent token behave the same from an access perspective (user is denied) so
it is safe to automatically remove all expired tokens.
"""

import argparse
from typing import TYPE_CHECKING

import requests
import transaction

from magpie import models
from magpie.cli.utils import make_logging_options, setup_logger_from_options
from magpie.constants import get_constant
from magpie.db import get_db_session_from_config_ini
from magpie.utils import get_logger, print_log, raise_log

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
    subparsers = parser.add_subparsers(help="run with API or directly access the database", dest="api_or_db")
    api_parser = subparsers.add_parser("api")
    _db_parser = subparsers.add_parser("db")

    api_parser.add_argument("url", help="URL used to access the magpie service.")
    api_parser.add_argument("username", help="Admin username for magpie login.")
    api_parser.add_argument("password", help="Admin password for magpie login.")
    make_logging_options(parser)
    return parser


def get_login_session(magpie_url, username, password):
    session = requests.Session()
    data = {"user_name": username, "password": password}
    response = session.post(magpie_url + "/signin", json=data)
    if response.status_code != 200:
        LOGGER.error(response.content)
        return None
    return session


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> None
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, args)
    if args.api_or_db == "api":
        session = get_login_session(args.url, args.username, args.password)
        if session is None:
            raise_log("Failed to login, invalid username or password", logger=LOGGER)
        response = session.delete("{}/network/tokens?expired_only=true".format(args.url))
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise_log("Failed to delete expired network tokens: {}".format(exc), exception=type(exc), logger=LOGGER)
        data = response.json()
        deleted = int(data["deleted"])
    else:
        db_session = get_db_session_from_config_ini(args.ini_config)
        deleted = models.NetworkToken.delete_expired(db_session)
        anonymous_network_user_ids = [n.anonymous_user(db_session).id for n in
                                      db_session.query(models.NetworkNode).all()]
        # clean up unused records in the database (no need to keep records associated with anonymous network users)
        (db_session.query(models.NetworkRemoteUser)
         .filter(models.NetworkRemoteUser.user_id.in_(anonymous_network_user_ids))
         .filter(models.NetworkRemoteUser.network_token_id == None)  # noqa: E711 # pylint: disable=singleton-comparison
         .delete())
        try:
            transaction.commit()
            db_session.close()
        except Exception as exc:  # noqa: W0703 # nosec: B110 # pragma: no cover
            db_session.rollback()
            raise_log("Failed to delete expired network tokens", exception=type(exc), logger=LOGGER)
    if deleted:
        print_log("{} expired network tokens deleted".format(deleted), logger=LOGGER)
    else:
        print_log("No expired network tokens found", logger=LOGGER)


if __name__ == "__main__":
    main()
