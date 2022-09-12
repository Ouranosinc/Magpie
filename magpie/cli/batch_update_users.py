#!/usr/bin/env python3
"""
Magpie helper to create or delete a list of users using a set of input parameters.

Useful for batch operations.
"""
import argparse
import datetime
import os
import uuid
from typing import TYPE_CHECKING

import requests

from magpie.cli.utils import make_logging_options, setup_logger_from_options
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

ERROR_PARAMS = 2
ERROR_EXEC = 1


def format_response(response):
    response_json = get_json(response)
    return str(response_json.get("code")) + " : " + str(response_json.get("detail"))


def get_login_session(magpie_url, username, password, return_response=False):
    session = requests.Session()
    data = {"user_name": username, "password": password}
    response = session.post(magpie_url + "/signin", json=data)
    fmt_resp = format_response(response)
    if return_response:
        return fmt_resp
    if response.status_code != 200:
        LOGGER.error(fmt_resp)
        return None
    return session


def create_users(user_config, magpie_url, magpie_admin_username, magpie_admin_password, password_length=None):
    # type: (UserConfig, Str, Str, Str, Optional[int]) -> UserConfig
    """
    Creates the users using provided configuration.

    :returns: updated configuration with generated user-credentials.
    """
    session = get_login_session(magpie_url, magpie_admin_username, magpie_admin_password)
    if not session:
        return []

    password_length = password_length or get_constant("MAGPIE_PASSWORD_MIN_LENGTH")
    for usr_cfg in user_config:
        if not usr_cfg.get("password"):
            LOGGER.warning("No password provided for user: '%s'. Will auto-generate random value.")
            usr_cfg["password"] = pseudo_random_string(length=password_length)
        data = {"user_name": usr_cfg["username"], "password": usr_cfg["password"],
                "group_name": usr_cfg["group"], "email": usr_cfg["email"]}
        response = session.post(magpie_url + "/users", json=data)
        if response.status_code != 201:
            usr_cfg["result"] = format_response(response)

    # test each successful users with a login
    for usr_cfg in user_config:
        if not usr_cfg.get("result"):
            usr_cfg["result"] = get_login_session(
                magpie_url, usr_cfg["username"], usr_cfg["password"], return_response=True
            )
    return user_config


def delete_users(user_config, magpie_url, magpie_admin_username, magpie_admin_password, **__):
    # type: (UserConfig, Str, Str, Str, **Any) -> UserConfig
    """
    Deletes the specified users.

    :returns: details about request success or failure for each user to be deleted.
    """
    session = get_login_session(magpie_url, magpie_admin_username, magpie_admin_password)
    if not session:
        return []

    users = []
    for user in user_config:
        if "username" not in user or not user["username"]:
            LOGGER.error("Cannot delete with missing username")
            users.append({"username": "<missing>", "result": "<skipped>"})
            continue
        response = session.delete(magpie_url + "/users/" + user["username"])
        users.append({"username": user["username"], "result": format_response(response)})
    return users


def make_output(user_results, is_delete, output_location=None):
    # type: (UserConfig, bool, Optional[Str]) -> None
    """
    Generates the output from obtained user creation/deletion results.
    """

    cols_space = 5
    cols_width = {"username": 8, "password": 8, "result": 8}
    for user in user_results:
        cols_width["username"] = max(cols_width["username"], len(user["username"]))
        cols_width["result"] = max(cols_width["result"], len(user["result"]))
        if not is_delete:
            cols_width["password"] = max(cols_width["password"], len(user["password"]))
    for col in cols_width:
        cols_width[col] += cols_space

    output = "\n" + "USERNAME".ljust(cols_width["username"]) + \
             ("PASSWORD".ljust(cols_width["password"]) if not is_delete else "") + \
             "RESULT".ljust(cols_width["result"]) + "\n"
    output += "".ljust(len(output), "_") + "\n\n"
    for user in user_results:
        output += user["username"].ljust(cols_width["username"]) + \
                  (user["password"].ljust(cols_width["password"]) if not is_delete else "") + \
                  user.get("result", "").ljust(cols_width["result"]) + "\n"  # noqa: E126

    oper_name = "delete" if is_delete else "create"
    filename = "magpie_" + oper_name + "_users_log__" + datetime.datetime.now().strftime("%Y%m%d__%H%M%S") + ".txt"
    if output_location:
        if not os.path.exists(output_location):
            os.makedirs(output_location)
        filename = os.path.join(output_location, filename)
    with open(filename, mode="w", encoding="utf-8") as file:
        file.write(output)
        LOGGER.info("Output results sent to [%s]", filename)


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Batch update users on a running Magpie instance.")
    parser.add_argument("url", help="URL used to access the magpie service.")
    parser.add_argument("username", help="Admin username for magpie login.")
    parser.add_argument("password", help="Admin password for magpie login.")
    parser.add_argument("-L", "--length", type=int,
                        help="Required length for passwords to be generated (must full Magpie conditions).")
    parser.add_argument("-D", "--delete", action="store_true", help="Delete users instead of creating them.")
    parser.add_argument("-o", "--output", help="Alternate output directory of results.")
    parser.add_argument("-f", "--file", help="Batch file listing user details to apply updates. "
                                             "See 'config/config.yml' for expected users/groups format.")
    parser.add_argument("-e", "--emails", nargs="*", default=[],
                        help="List of emails for users to be created. "
                             "User names will be auto-generated if not provided.")
    parser.add_argument("-u", "--users", nargs="*", default=[],
                        help="List of user names corresponding to emails.")
    parser.add_argument("-g", "--group", help="Common group applied to all users (when using emails) "
                                              "or if missing (when using file). Defaults to no group association.")
    make_logging_options(parser)
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[Str]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)
    setup_logger_from_options(LOGGER, args)

    if args.file:
        users_cfg = []
        for cfg in get_all_configs(args.file, "users"):
            for user in cfg:
                user.setdefault("group", args.group)
            users_cfg.extend(cfg)
    elif args.emails or args.delete:
        if args.users:
            names = args.users
        elif args.delete:
            LOGGER.error("No users to delete. User names are needed for this operation.")
            return ERROR_PARAMS
        else:
            names = [str(uuid.uuid4()) for _ in range(len(args.emails))]
        if not args.delete and len(names) != len(args.emails):
            LOGGER.error("Invalid user names/email counts.")
            return ERROR_PARAMS
        if args.delete:
            users_cfg = [{"username": name} for name in names]
        else:
            users_cfg = [{"username": name, "email": email, "group": args.group}
                         for name, email in zip(names, args.emails)]
    else:
        LOGGER.error("Either batch file, user names or emails must be provided for processing.")
        return ERROR_PARAMS

    oper_name = "delete" if args.delete else "create"
    if len(users_cfg) == 0:
        LOGGER.warning("No users to %s", oper_name)
        return ERROR_EXEC
    oper_users = delete_users if args.delete else create_users
    users = oper_users(users_cfg, args.url, args.username, args.password, password_length=args.length)
    make_output(users, args.delete, args.output)
    return 0


if __name__ == "__main__":
    main()
