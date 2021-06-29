#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from typing import TYPE_CHECKING

from magpie.utils import set_logger_config

if TYPE_CHECKING:
    import argparse


def make_logging_options(parser):
    # type: (argparse.ArgumentParser) -> None
    """
    Defines argument parser options for logging operations.
    """
    log_opts = parser.add_argument_group(title="Logging Options", description="Options that configure output logging.")
    log_opts.add_argument("--stdout", action="store_true", help="Enforce logging to stdout for display in console.")
    log_opts.add_argument("--log", "--log-file", help="Output file to write generated logs.")
    lvl_opts = log_opts.add_mutually_exclusive_group()
    lvl_opts.add_argument("--quiet", "-q", action="store_true", help="Do not output anything else than error.")
    lvl_opts.add_argument("--debug", "-d", action="store_true", help="Enable extra debug logging.")
    lvl_opts.add_argument("--verbose", "-v", action="store_true", help="Output informative logging details.")
    lvl_names = ["debug", "info", "warn", "error"]
    lvl_opts.add_argument("--log-level", "-l", dest="log_level",
                          choices=list(sorted(lvl_names + [lvl.upper() for lvl in lvl_names])),
                          help="Explicit log level to employ (default: %(default)s).")


def setup_logger_from_options(logger, args):
    # type: (logging.Logger, argparse.Namespace) -> None
    """
    Uses argument parser options to setup logging level from specified flags.

    Setup both the specific CLI logger that is provided and the generic `magpie` logger.
    """
    if args.log_level:
        logger.setLevel(logging.getLevelName(args.log_level.upper()))
    elif args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    elif args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.WARNING)
    set_logger_config(logger, force_stdout=args.stdout, )
    if logger.name != "magpie":
        setup_logger_from_options(logging.getLogger("magpie"), args)
