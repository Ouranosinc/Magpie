#!/usr/bin/env python3
"""
Magpie helper to create or delete a list of users using a set of input parameters.

Useful for batch operations.
"""
import argparse
import datetime
import logging
import os
import sys
import uuid
from typing import TYPE_CHECKING

import requests

from magpie.register import get_all_configs, pseudo_random_string

if TYPE_CHECKING:
    from typing import Any, AnyStr, Optional, Sequence

LOGGER = logging.getLogger(__name__)
COLUMN_SIZE = 60
ERROR_PARAMS = 2
ERROR_EXEC = 1


def format_response(response):
    response_json = response.json()
    return str(response_json.get("code")) + " : " + response_json.get("detail")


def create_users(user_config, magpie_url, magpie_admin_user_name, magpie_admin_password):
    session = requests.Session()
    response = session.post(magpie_url + "/signin", data={"user_name": magpie_admin_user_name,
                                                          "password": magpie_admin_password,
                                                          "provider_name": "ziggurat"})
    if not response.ok:
        LOGGER.error(format_response(response))
        return []

    users = []
    for usr_cfg in user_config:
        user = {
            "email": usr_cfg["email"],
            "user_name": usr_cfg["username"],
            "password": pseudo_random_string(),
            "group_name": usr_cfg.get("group_name", None),  # request will handle default
        }
        users.append(user)
    for user in users:
        response = session.post(magpie_url + "/users", data=user)
        if not response.ok:
            user["result"] = format_response(response)

    # test each successful users with a login
    for user in users:
        if not user.get("result"):
            session = requests.Session()
            response = session.post(magpie_url + "/signin",
                                    data={"user_name": user["user_name"], "password": user["password"]})
            user["result"] = format_response(response)
    return users


def delete_users(user_config, magpie_url, magpie_admin_user_name, magpie_admin_password):
    session = requests.Session()
    response = session.post(magpie_url + "/signin", data={"user_name": magpie_admin_user_name,
                                                          "password": magpie_admin_password,
                                                          "provider_name": "ziggurat"})
    if not response.ok:
        LOGGER.error(format_response(response))
        return []

    users = []
    for user in user_config:
        if "username" not in user or not user["username"]:
            LOGGER.error("Cannot delete with missing username")
            users.append({"user_name": "<missing>", "result": "<skipped>"})
            continue
        response = session.delete(magpie_url + "/users/" + user["username"])
        users.append({"user_name": user, "result": format_response(response)})
    return users


def make_parser():
    # type: () -> argparse.ArgumentParser
    parser = argparse.ArgumentParser(description="Batch update users on a running Magpie instance.")
    parser.add_argument("url", help="URL used to access the magpie service.")
    parser.add_argument("username", help="Admin username for magpie login.")
    parser.add_argument("password", help="Admin password for magpie login.")
    parser.add_argument("-d", "--delete", action="store_true", help="Delete users instead of creating them.")
    parser.add_argument("-o", "--output", help="Alternate output directory of results.")
    parser.add_argument("-q", "--quiet", help="Suppress informative logging.")
    parser.add_argument("-f", "--file", help="Batch file listing user details to apply updates. "
                                             "See 'config/config.yml' for expected users/groups format.")
    parser.add_argument("-e", "--emails", nargs="*", help="List of emails for users to be created. "
                                                          "User names will be auto-generated if not provided.")
    parser.add_argument("-u", "--users", nargs="*", help="List of user names corresponding to emails.")
    parser.add_argument("-g", "--group", help="Group applied to all users (when using emails) "
                                              "or if missing (when using file). Defaults to no group association.")
    return parser


def main(args=None, parser=None, namespace=None):
    # type: (Optional[Sequence[AnyStr]], Optional[argparse.ArgumentParser], Optional[argparse.Namespace]) -> Any
    if not parser:
        parser = make_parser()
    args = parser.parse_args(args=args, namespace=namespace)

    LOGGER.setLevel(logging.WARNING if args.quiet else logging.DEBUG)
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%d-%b-%y %H:%M:%S")
    oper_users = delete_users if args.delete else create_users
    oper_name = "delete" if args.delete else "create"

    if args.file:
        users_cfg = get_all_configs(args.file, "users")
        for user in users_cfg:
            user.setdefault("group", args.group)
    elif args.emails or args.delete:
        if args.users:
            names = args.users
        elif args.delete:
            LOGGER.error("No users to delete. User names are needed for this operation.")
            return ERROR_PARAMS
        else:
            names = [str(uuid.uuid4()) for _ in range(len(args.emails))]
        if len(names) != len(args.emails):
            LOGGER.error("Invalid user names/email counts.")
            return ERROR_PARAMS
        users_cfg = [{"username": name, "email": email, "group": args.group} for name, email in zip(names, args.emails)]
    else:
        LOGGER.error("Either batch file, user names or emails must be provided for processing.")
        return ERROR_PARAMS

    users = oper_users(users_cfg, args.url, args.username, args.password)
    if len(users) == 0:
        LOGGER.warning("No users to %s", oper_name)
        return ERROR_EXEC
    else:
        output = "\nUSERNAME".ljust(COLUMN_SIZE) + \
                 ("PASSWORD".ljust(COLUMN_SIZE) if not args.delete else "") + \
                 "RESULT".ljust(COLUMN_SIZE) + "\n"
        output += "".ljust(COLUMN_SIZE * 3, "_") + "\n\n"
        for user in users:
            output += user["user_name"].ljust(COLUMN_SIZE) + \
                      (user["password"].ljust(COLUMN_SIZE) if not args.delete else "") + \
                      user.get("result", "").ljust(COLUMN_SIZE) + "\n"  # noqa: E126

        LOGGER.info(output)

        filename = oper_name + "_users_log__" + datetime.datetime.now().strftime("%Y%m%d__%H%M%S") + ".txt"
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            filename = os.path.join(args.output, filename)
        with open(filename, "w") as file:
            file.write(output)
            LOGGER.info("Output results sent to [%s]", filename)


if __name__ == "__main__":
    sys.exit(main())
