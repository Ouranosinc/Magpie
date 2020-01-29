#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import sys
from typing import TYPE_CHECKING

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
if TYPE_CHECKING:
    from typing import Iterable, Set

MAGPIE_ROOT = os.path.abspath(os.path.dirname(__file__))
MAGPIE_MODULE_DIR = os.path.join(MAGPIE_ROOT, "magpie")
sys.path.insert(0, MAGPIE_MODULE_DIR)
# do not use 'from magpie' to avoid import error on not yet installed packages
import __meta__  # isort:skip # noqa: E402

LOGGER = logging.getLogger("magpie.setup")
if logging.StreamHandler not in LOGGER.handlers:
    LOGGER.addHandler(logging.StreamHandler(sys.stdout))  # type: ignore # noqa
LOGGER.setLevel(logging.INFO)
LOGGER.info("starting setup")


with open("README.rst") as readme_file:
    README = readme_file.read()

with open("HISTORY.rst") as history_file:
    HISTORY = history_file.read().replace(".. :changelog:", "")


def _parse_requirements(file_path, requirements, links):
    # type: (str, Set[str], Set[str]) -> None
    """
    Parses a requirements file to extra packages and links.

    :param file_path: file path to the requirements file.
    :param requirements: pre-initialized set in which to store extracted package requirements.
    :param links: pre-initialized set in which to store extracted link reference requirements.
    :returns: None
    """
    with open(file_path, 'r') as requirements_file:
        for line in requirements_file:
            # ignore empty line, comment line or reference to other requirements file (-r flag)
            if not line or line.startswith('#') or line.startswith("-"):
                continue
            if "git+https" in line:
                pkg = line.split("#")[-1]
                links.add(line.strip())
                requirements.add(pkg.replace("egg=", "").rstrip())
            elif line.startswith("http"):
                links.add(line.strip())
            else:
                requirements.add(line.strip())


def _extra_requirements(base_requirements, other_requirements):
    # type: (Iterable[str], Iterable[str]) -> Set[str]
    """
    Extracts only the extra requirements not already defined within the base requirements.

    :param base_requirements: base package requirements.
    :param other_requirements: other set of requirements referring to additional dependencies.
    """
    raw_requirements = set()
    for req in base_requirements:
        raw_req = req.split('>')[0].split('=')[0].split('<')[0].split('!')[0]
        raw_requirements.add(raw_req)
    filtered_test_requirements = set()
    for req in other_requirements:
        raw_req = req.split('>')[0].split('=')[0].split('<')[0].split('!')[0]
        if raw_req not in raw_requirements:
            filtered_test_requirements.add(req)
    return filtered_test_requirements


LOGGER.info("reading requirements")

# See https://github.com/pypa/pip/issues/3610
# use set to have unique packages by name
LINKS = set()
REQUIREMENTS = set()
DOCS_REQUIREMENTS = set()
TEST_REQUIREMENTS = set()
_parse_requirements("requirements.txt", REQUIREMENTS, LINKS)
_parse_requirements("requirements-py{}.txt".format(sys.version[0]), REQUIREMENTS, LINKS)
_parse_requirements("requirements-docs.txt", DOCS_REQUIREMENTS, LINKS)
_parse_requirements("requirements-dev.txt", TEST_REQUIREMENTS, LINKS)
LINKS = list(LINKS)
REQUIREMENTS = list(REQUIREMENTS)
DOCS_REQUIREMENTS = list(_extra_requirements(REQUIREMENTS, DOCS_REQUIREMENTS))
TEST_REQUIREMENTS = list(_extra_requirements(REQUIREMENTS, TEST_REQUIREMENTS))

LOGGER.info("base requirements: %s", REQUIREMENTS)
LOGGER.info("docs requirements: %s", DOCS_REQUIREMENTS)
LOGGER.info("test requirements: %s", TEST_REQUIREMENTS)
LOGGER.info("link requirements: %s", LINKS)

setup(
    # -- meta information --------------------------------------------------
    name=__meta__.__package__,
    version=__meta__.__version__,
    description=__meta__.__description__,
    long_description=README + '\n\n' + HISTORY,
    author=__meta__.__author__,
    maintainer=__meta__.__maintainer__,
    maintainer_email=__meta__.__email__,
    contact=__meta__.__maintainer__,
    contact_email=__meta__.__email__,
    url=__meta__.__url__,
    platforms=__meta__.__platforms__,
    license=__meta__.__license__,
    keywords=__meta__.__title__ + ", Authentication, AuthN, Birdhouse",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    # -- Package structure -------------------------------------------------
    packages=[__meta__.__package__],
    package_dir={__meta__.__package__: __meta__.__package__},
    include_package_data=True,
    install_requires=REQUIREMENTS,
    dependency_links=LINKS,
    extras_require={
        "docs": DOCS_REQUIREMENTS,
        "dev": TEST_REQUIREMENTS,
        "test": TEST_REQUIREMENTS,
    },
    zip_safe=False,

    # -- self - tests --------------------------------------------------------
    # test_suite='nose.collector',
    # test_suite='tests.test_runner',
    # test_loader='tests.test_runner:run_suite',
    test_suite='tests',
    tests_require=TEST_REQUIREMENTS,

    # -- script entry points -----------------------------------------------
    entry_points={
        "paste.app_factory": [
            "main = magpie.app:main"
        ],
        "console_scripts": [
            "create_users = magpie.helpers.create_users:main",
            "register_default_users = magpie.helpers.register_default_users:register_default_users",
            "register_providers = magpie.helpers.register_providers:main",
            "run_database_migration = magpie.helpers.run_database_migration:run_database_migration",
            "sync_resources = magpie.helpers.sync_resources:main",
        ],
    }
)
LOGGER.info("setup complete")
