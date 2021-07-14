#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_cli
----------------------------------

Tests for :mod:`magpie.cli` module.
"""

import json
import os
import subprocess
import tempfile

import mock
import six

from magpie.cli import batch_update_users, magpie_helper_cli
from magpie.constants import get_constant
from tests import runner, utils

if six.PY2:
    from backports import tempfile as tempfile2  # noqa  # pylint: disable=E0611,no-name-in-module  # Python 2
else:
    tempfile2 = tempfile  # pylint: disable=C0103,invalid-name

KNOWN_HELPERS = [
    "batch_update_users",
    "register_defaults",
    "register_providers",
    "run_db_migration",
    "send_email",
    "sync_resources"
]


def run_and_get_output(command, trim=True):
    if isinstance(command, (list, tuple)):
        command = " ".join(command)
    env = {"PATH": os.path.expandvars(os.environ["PATH"])}  # when debugging, explicit expand of install path required
    proc = subprocess.Popen(command, shell=True, env=env, universal_newlines=True, stdout=subprocess.PIPE)  # nosec
    out, err = proc.communicate()
    assert not err, "process returned with error code {}".format(err)
    # when no output is present, it is either because CLI was not installed correctly, or caused by some other error
    assert out != "", "process did not execute as expected, no output available"
    out_lines = [line for line in out.splitlines() if not trim or (line and not line.startswith(" "))]
    assert len(out_lines), "could not retrieve any console output"
    return out_lines


def magpie_cli_helper_alias(alias):
    out_lines = run_and_get_output(alias + " --help", trim=False)
    assert "usage: " + alias in out_lines[0]
    assert all([helper in out_lines[1] for helper in KNOWN_HELPERS])


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_cli_help():
    magpie_cli_helper_alias("magpie_cli")


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_helper_help():
    magpie_cli_helper_alias("magpie_helper")


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_helper_as_python():
    for helper in KNOWN_HELPERS:
        args = [helper, "--help"]
        try:
            magpie_helper_cli(args)
        except SystemExit as exc:
            assert exc.code == 0, "success output expected, non-zero or not None are errors"
        except Exception as exc:
            raise AssertionError("unexpected error raised instead of success exit code: [{!s}]".format(exc))
        else:
            raise AssertionError("expected exit code on help call not raised")


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_batch_update_users_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper batch_update_users --help")
    assert "usage: magpie_helper batch_update_users" in out_lines[0]
    assert "Batch update users on a running Magpie instance" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_batch_update_users_help_directly():
    out_lines = run_and_get_output("magpie_batch_update_users --help")
    assert "usage: magpie_batch_update_users" in out_lines[0]
    assert "Batch update users on a running Magpie instance" in out_lines[1]


def run_batch_update_user_command(test_app, expected_users, create_command_xargs, delete_command_xargs):
    """
    Tests batch user creation and deletion of the CLI utility.

    Because CLI utility employs requests that cannot be mocked if executed through sub-process, we call it directly.
    """
    test_admin_usr = get_constant("MAGPIE_TEST_ADMIN_USERNAME", raise_not_set=False, raise_missing=False)
    test_admin_pwd = get_constant("MAGPIE_TEST_ADMIN_PASSWORD", raise_not_set=False, raise_missing=False)
    if not test_admin_usr or not test_admin_pwd:
        test_admin_usr = get_constant("MAGPIE_ADMIN_USER")
        test_admin_pwd = get_constant("MAGPIE_ADMIN_PASSWORD")
    test_url = "http://localhost"

    def mock_request(*args, **kwargs):
        method, url, args = args[0], args[1], args[2:]
        path = url.replace(test_url, "")
        # because CLI utility does multiple login tests, we must force TestApp logout to forget session
        # otherwise, error is raised because of user session mismatch between previous login and new one requested
        if path.startswith("/signin"):
            utils.check_or_try_logout_user(test_app)
        return utils.test_request(test_app, method, path, *args, **kwargs)

    def run_command(operation_name, operation_args):
        with tempfile2.TemporaryDirectory() as tmpdir:
            with mock.patch("requests.Session.request", side_effect=mock_request):
                with mock.patch("requests.request", side_effect=mock_request):
                    cmd = [test_url, test_admin_usr, test_admin_pwd, "-o", tmpdir] + operation_args
                    assert batch_update_users.main(cmd) == 0, "failed execution due to invalid arguments"
                    assert len(os.listdir(tmpdir)) == 1, "utility should have produced 1 output file"
                    file = os.path.join(tmpdir, os.listdir(tmpdir)[0])
                    utils.check_val_is_in(operation_name, file)
                    assert os.path.isfile(file)
                    with open(file, "r") as fd:
                        file_text = fd.read()
                    assert all([test_user in file_text for test_user in expected_users]), \
                        "all users should have been processed and logged in output result file"

    # cleanup in case of previous failure
    _, test_admin_cookies = utils.check_or_try_login_user(test_app, username=test_admin_usr, password=test_admin_pwd)
    for user in expected_users:
        utils.TestSetup.delete_TestUser(test_app, override_user_name=user,  # noqa
                                        override_headers={}, override_cookies=test_admin_cookies)
    utils.check_or_try_logout_user(test_app)

    # test user creation and validate that users were all created
    run_command("create", create_command_xargs)
    utils.check_or_try_logout_user(test_app)
    _, test_admin_cookies = utils.check_or_try_login_user(test_app, username=test_admin_usr, password=test_admin_pwd)
    resp = utils.test_request(test_app, "GET", "/users", cookies=test_admin_cookies)
    body = utils.check_response_basic_info(resp)
    for user in expected_users:
        utils.check_val_is_in(user, body["user_names"])

    # test user deletion and validate users are all deleted
    run_command("delete", ["-D"] + delete_command_xargs)
    utils.check_or_try_logout_user(test_app)
    _, test_admin_cookies = utils.check_or_try_login_user(test_app, username=test_admin_usr, password=test_admin_pwd)
    resp = utils.test_request(test_app, "GET", "/users", cookies=test_admin_cookies)
    body = utils.check_response_basic_info(resp)
    for user in expected_users:
        utils.check_val_not_in(user, body["user_names"])


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_FUNCTIONAL
def test_magpie_batch_update_users_validate_operations_from_args():
    test_users = ["unittest-batch-register-user-args-{}".format(i) for i in range(1, 4)]
    test_app = utils.get_test_magpie_app()
    test_args_create = ["-u"] + test_users + ["-e"] + ["{}@email.com".format(user) for user in test_users]
    test_args_delete = ["-u"] + test_users
    run_batch_update_user_command(test_app, test_users, test_args_create, test_args_delete)


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
@runner.MAGPIE_TEST_FUNCTIONAL
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
    assert "Registers default users and groups in Magpie" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_register_defaults_help_directly():
    out_lines = run_and_get_output("magpie_register_defaults --help")
    assert "usage: magpie_register_defaults" in out_lines[0]
    assert "Registers default users and groups in Magpie" in out_lines[1]


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
def test_magpie_send_email_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper send_email --help")
    assert "usage: magpie_helper send_email" in out_lines[0]
    assert "Sends email notification using SMTP connection" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_send_email_help_directly():
    out_lines = run_and_get_output("magpie_send_email --help")
    assert "usage: magpie_send_email" in out_lines[0]
    assert "Sends email notification using SMTP connection" in out_lines[1]


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
