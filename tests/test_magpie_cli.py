#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_cli
----------------------------------

Tests for :mod:`magpie.cli` module.
"""

import json
import mock
import subprocess
import tempfile

from magpie.constants import get_constant
from tests import runner, utils

KNOWN_HELPERS = [
    "batch_update_users",
    "register_defaults",
    "register_providers",
    "run_db_migration",
    "sync_resources"
]


def run_and_get_output(command, trim=True):
    proc = subprocess.Popen(command, shell=True, universal_newlines=True, stdout=subprocess.PIPE)
    out, err = proc.communicate()
    assert not err
    out_lines = [line for line in out.splitlines() if not trim or (line and not line.startswith(" "))]
    return out_lines


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_helper_help():
    out_lines = run_and_get_output("magpie_helper --help", trim=False)
    assert "usage: magpie_helper" in out_lines[0]
    assert all([helper in out_lines[1] for helper in KNOWN_HELPERS])


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_batch_update_users_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper batch_update_users --help")
    assert "usage: magpie_helper batch_update_users" in out_lines[0]
    assert "Create users on a running Magpie instance" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_batch_update_users_help_directly():
    out_lines = run_and_get_output("magpie_batch_update_users --help")
    assert "usage: magpie_batch_update_users" in out_lines[0]
    assert "Create users on a running Magpie instance" in out_lines[1]


def run_batch_update_user_command(test_app, expected_users, create_command_xargs, delete_command_xargs):
    """Tests batch user creation and deletion of the CLI utility."""
    test_admin_usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME")
    test_admin_pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD")
    test_url = "http://mock.test"

    def mock_request(*args, **kwargs):
        url, args = args[0], args[1:]
        path = url.replace(test_url, "")
        return utils.test_request(test_app, path, *args, **kwargs)

    # cleanup in case of previous failure
    utils.check_or_try_login_user(test_app, username=test_admin_usr, password=test_admin_pwd)
    for user in expected_users:
        utils.TestSetup.delete_TestUser(test_app, override_user_name=user,  # noqa
                                        override_headers={}, override_cookies=test_app.cookies)
    utils.check_or_try_logout_user(test_app)

    # test user creation
    with mock.patch("requests.Session.request", side_effect=mock_request):
        cmd = ["magpie_batch_update_users", test_url, test_admin_usr, test_admin_pwd] + create_command_xargs
        run_and_get_output(cmd)

    # validate that users were all created
    utils.check_or_try_login_user(test_app, username=test_admin_usr, password=test_admin_pwd)
    resp = utils.test_request(test_app, "GET", "/users")
    body = utils.check_response_basic_info(resp)
    for user in expected_users:
        utils.check_val_is_in(user, body["user_names"])

    # test user deletion
    with mock.patch("requests.Session.request", side_effect=mock_request):
        cmd = ["-d", "magpie_batch_update_users", test_url, test_admin_usr, test_admin_pwd] + delete_command_xargs
        run_and_get_output(cmd)

    # validate users are all deleted
    utils.check_or_try_login_user(test_app, username=test_admin_usr, password=test_admin_pwd)
    resp = utils.test_request(test_app, "GET", "/users")
    body = utils.check_response_basic_info(resp)
    for user in expected_users:
        utils.check_val_not_in(user, body["user_names"])


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_batch_update_users_validate_operations_from_args():
    test_users = ["unittest-batch-register-user-args-{}".format(i) for i in range(1, 4)]
    test_app = utils.get_test_magpie_app()
    test_args_create = []
    test_args_delete = []
    for user in test_users:
        test_args_create.extend(["-e", "{}@email.com".format(user), "-u", user])
        test_args_delete.extend(["-u", user])
    run_batch_update_user_command(test_app, test_users, test_args_create, test_args_delete)


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_batch_update_users_validate_operations_from_file():
    test_users = ["unittest-batch-register-user-file-{}".format(i) for i in range(1, 4)]
    test_app = utils.get_test_magpie_app()
    user_config = {
        "users": [{"username": user, "email": "{}@email.com".format(user)} for user in test_users]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as tmp_file:
        tmp_file.write(json.dumps(user_config))
        tmp_file.seek(0)
        test_args = ["-f", tmp_file.name]
        run_batch_update_user_command(test_app, test_users, test_args, test_args)


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_register_defaults_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper register_defaults --help")
    assert "usage: magpie_helper register_defaults" in out_lines[0]
    assert "Registers default users in Magpie" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_register_defaults_help_directly():
    out_lines = run_and_get_output("magpie_register_defaults --help")
    assert "usage: magpie_register_defaults" in out_lines[0]
    assert "Registers default users in Magpie" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_register_providers_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper register_providers --help")
    assert "usage: magpie_helper register_providers" in out_lines[0]
    assert "Register service providers into Magpie" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_register_providers_help_directly():
    out_lines = run_and_get_output("magpie_register_providers --help")
    assert "usage: magpie_register_providers" in out_lines[0]
    assert "Register service providers into Magpie" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_run_db_migration_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper run_db_migration --help")
    assert "usage: magpie_helper run_db_migration" in out_lines[0]
    assert "Run Magpie database migration." in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_run_db_migration_help_directly():
    out_lines = run_and_get_output("magpie_run_db_migration --help")
    assert "usage: magpie_run_db_migration" in out_lines[0]
    assert "Run Magpie database migration." in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_sync_resources_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper sync_resources --help")
    assert "usage: magpie_helper sync_resources" in out_lines[0]
    assert "Synchronize local and remote resources based on Magpie Service sync-type" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_sync_resources_help_directly():
    out_lines = run_and_get_output("magpie_sync_resources --help")
    assert "usage: magpie_sync_resources" in out_lines[0]
    assert "Synchronize local and remote resources based on Magpie Service sync-type" in out_lines[1]
