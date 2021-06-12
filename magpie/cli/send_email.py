#!/usr/bin/env python3
"""
Magpie helper to send email notification using SMTP connection defined from configuration.

Useful for validation of SMTP settings retrieved from an INI file or debugging the rendered email contents.
"""
import argparse
import datetime
import logging
import os
import uuid
from typing import TYPE_CHECKING

import requests

from magpie.constants import get_constant
from magpie.register import get_all_configs, pseudo_random_string
from magpie.utils import get_json, get_logger

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional, Sequence

    from magpie.typedefs import Str
    UserConfig = List[Dict[Str, Str]]

LOGGER = get_logger(__name__,
                    message_format="%(asctime)s - %(levelname)s - %(message)s",
                    datetime_format="%d-%b-%y %H:%M:%S", force_stdout=False)


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Batch update users on a running Magpie instance.")
    parser.add_argument("-e", "--email", required=True, help="Address where to sent the test email.")
    parser.add_argument("-c", "--config", "--ini", metavar="CONFIG", dest="config",
                        help="Configuration INI file to retrieve application settings.")

    parser.add_argument("-q", "--quiet", help="Suppress informative logging.")
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    LOGGER.setLevel(logging.WARNING if args.quiet else logging.DEBUG)
    #template = select_email(args.email)
    #make_output(users, args.delete, args.output)
    return 0


if __name__ == "__main__":
    main()
