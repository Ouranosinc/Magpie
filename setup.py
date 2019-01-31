#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
MAGPIE_ROOT = os.path.abspath(os.path.dirname(__file__))
MAGPIE_MODULE_DIR = os.path.join(MAGPIE_ROOT, 'magpie')
sys.path.insert(0, MAGPIE_MODULE_DIR)

from setuptools import find_packages    # noqa: F401
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
from magpie import __meta__             # noqa: F401

with open('README.rst') as readme_file:
    README = readme_file.read()

with open('HISTORY.rst') as history_file:
    HISTORY = history_file.read().replace('.. :changelog:', '')


def _parse_requirements(file_path, requirements, links):
    with open(file_path, 'r') as requirements_file:
        for line in requirements_file:
            if 'git+https' in line:
                pkg = line.split('#')[-1]
                links.add(line.strip())
                requirements.add(pkg.replace('egg=', '').rstrip())
            elif line.startswith('http'):
                links.add(line.strip())
            else:
                requirements.add(line.strip())


# See https://github.com/pypa/pip/issues/3610
# use set to have unique packages by name
LINKS = set()
REQUIREMENTS = set()
TEST_REQUIREMENTS = set()
_parse_requirements('requirements.txt', REQUIREMENTS, LINKS)
_parse_requirements('requirements-py{}.txt'.format(sys.version[0]), REQUIREMENTS, LINKS)
_parse_requirements('requirements-dev.txt', TEST_REQUIREMENTS, LINKS)
LINKS = list(LINKS)
REQUIREMENTS = list(REQUIREMENTS)
TEST_REQUIREMENTS = list(TEST_REQUIREMENTS)

raw_requirements = set()
for req in REQUIREMENTS:
    raw_req = req.split('>')[0].split('=')[0].split('<')[0].split('!')[0]
    raw_requirements.add(raw_req)
filtered_test_requirements = set()
for req in TEST_REQUIREMENTS:
    raw_req = req.split('>')[0].split('=')[0].split('<')[0].split('!')[0]
    if raw_req not in raw_requirements:
        filtered_test_requirements.add(req)
TEST_REQUIREMENTS = list(filtered_test_requirements)

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
    packages=find_packages(),
    package_dir={__meta__.__package__: 'magpie'},
    include_package_data=True,
    install_requires=REQUIREMENTS,
    dependency_links=LINKS,
    zip_safe=False,

    # -- self - tests --------------------------------------------------------
    # test_suite='nose.collector',
    # test_suite='tests.test_runner',
    # test_loader='tests.test_runner:run_suite',
    tests_require=TEST_REQUIREMENTS,

    # -- script entry points -----------------------------------------------
    entry_points="""\
          [paste.app_factory]
          main = magpie.magpiectl:main
          [console_scripts]
          """,
)
