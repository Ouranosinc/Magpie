#!/usr/bin/env python3
"""
Magpie helper to create or delete a set of permissions.

When parsing permissions to create, any underlying user, group, service or resource
that are missing, but that can be resolved with reasonable defaults, will be dynamically
created prior to setting the corresponding permission on it.

See https://pavics-magpie.readthedocs.io/en/latest/configuration.html#file-permissions-cfg for more details.
"""
import argparse
from typing import TYPE_CHECKING

import yaml

from magpie.cli.utils import make_logging_options, setup_logger_from_options
from magpie.register import get_all_configs, magpie_register_permissions_from_config
from magpie.utils import get_logger

if TYPE_CHECKING:
    from typing import Any, Optional, Sequence

LOGGER = get_logger(__name__,
                    message_format="%(asctime)s - %(levelname)s - %(message)s",
                    datetime_format="%d-%b-%y %H:%M:%S", force_stdout=False)

ERROR_PARAMS = 2
ERROR_EXEC = 1


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-u", "--url", "--magpie-url", help=(
        "URL used to access the magpie service (if omitted, will try using 'MAGPIE_URL' environment variable)."
    ))
    parser.add_argument("-U", "--username", "--magpie-admin-user", help=(
        "Admin username for magpie login (if omitted, will try using 'MAGPIE_ADMIN_USER' environment variable)."
    ))
    parser.add_argument("-P", "--password", "--magpie-admin-password", help=(
        "Admin password for magpie login (if omitted, will try using 'MAGPIE_ADMIN_PASSWORD' environment variable)."
    ))
    parser.add_argument("-c", "--config", required=True, nargs="+", help=(
        "Path to a single configuration file or a directory containing configuration file that contains permissions. "
        "The option can be specified multiple times to provide multiple lookup directories or specific files to load. "
        "Configuration files must be in JSON or YAML format, with their respective extensions, or the '.cfg' extension."
    ))
    make_logging_options(parser)
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    ns = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, ns)

    all_configs = []
    for cfg in ns.config:
        configs = get_all_configs(cfg, "permissions", allow_missing=True)
        all_configs.extend(configs)

    if ns.verbose:
        LOGGER.info(
            "Resolved permissions to update:\n\n%s\n",
            yaml.safe_dump(all_configs, allow_unicode=True, encoding="utf-8", indent=4, sort_keys=False)
        )

    if not all_configs or all(not cfg for cfg in all_configs):
        LOGGER.error("Could not find any permissions configuration under specified locations.")
        return ERROR_PARAMS
    try:
        magpie_register_permissions_from_config(all_configs)
    except Exception as exc:
        LOGGER.error("Failed permissions parsing and update from specified configurations [%s].", str(exc))
        return ERROR_EXEC
    return 0


if __name__ == "__main__":
    main()
