#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Smoke test for magpie application.
"""
from magpie.db import get_engine
from magpie.models import *  # noqa # import all to define all models that inherit from 'Base'


def setup_mock_db_for_memory():
    """Generates the minimal database configuration required to boot Magpie without error."""
    engine = get_engine({
        "magpie.db_url": "sqlite:///tmp/db.db",
        "magpie.db_migration": False,
    })
    Base.metadata.create_all(engine)


if __name__ == "__main__":
    setup_mock_db_for_memory()
