#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_magpie_helpers
----------------------------------

Tests for :mod:`magpie.helpers` module.
"""

import subprocess

from tests import runner

KNOWN_HELPERS = [
    "create_users",
    "register_default_users",
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
def test_magpie_create_users_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper create_users --help")
    assert "usage: magpie_helper create_users" in out_lines[0]
    assert "Create users on a running Magpie instance" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_create_users_help_directly():
    out_lines = run_and_get_output("magpie_create_users --help")
    assert "usage: magpie_create_users" in out_lines[0]
    assert "Create users on a running Magpie instance" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_register_default_users_help_via_magpie_helper():
    out_lines = run_and_get_output("magpie_helper register_default_users --help")
    assert "usage: magpie_helper register_default_users" in out_lines[0]
    assert "Registers default users in Magpie" in out_lines[1]


@runner.MAGPIE_TEST_CLI
@runner.MAGPIE_TEST_LOCAL
def test_magpie_register_default_users_help_directly():
    out_lines = run_and_get_output("magpie_register_default_users --help")
    assert "usage: magpie_register_default_users" in out_lines[0]
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
