#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
MAGPIE_ROOT = os.path.abspath(os.path.dirname(__file__))
MAGPIE_MODULE_DIR = os.path.join(MAGPIE_ROOT, 'magpie')
sys.path.insert(0, MAGPIE_MODULE_DIR)

from setuptools import find_packages
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from magpie import __meta__

with open('README.rst') as readme_file:
    README = readme_file.read()

with open('HISTORY.rst') as history_file:
    HISTORY = history_file.read().replace('.. :changelog:', '')

LINKS = set()         # See https://github.com/pypa/pip/issues/3610
REQUIREMENTS = set()  # use set to have unique packages by name
with open('requirements.txt', 'r') as requirements_file:
    for line in requirements_file:
        if 'git+https' in line:
            pkg = line.split('#')[-1]
            LINKS.add(line.strip() + '-0')
            REQUIREMENTS.add(pkg.replace('egg=', '').rstrip())
        else:
            REQUIREMENTS.add(line.strip())

LINKS = list(LINKS)
REQUIREMENTS = list(REQUIREMENTS)

# put package test requirements here
TEST_REQUIREMENTS = [
    'nose==1.3.7',
    'webtest',
    'pytest',
]

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
    name='magpie',
    version=__meta__.__version__,
    description=__meta__.__description__,
    long_description=README + '\n\n' + HISTORY,
    author=__meta__.__author__,
    maintainer=__meta__.__maintainer__,
    maintainer_email=__meta__.__email__,
    contact=__meta__.__maintainer__,
    contact_email=__meta__.__email__,
    url=__meta__.__url__,
    platforms=['linux_x86_64'],
    license="ISCL",
    keywords='magpie',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],

    # -- Package structure -------------------------------------------------
    #packages=[
    #    'magpie',
    #],
    packages=find_packages(),
    package_dir={'magpie': 'magpie'},
    include_package_data=True,
    install_requires=REQUIREMENTS,
    dependency_links=LINKS,
    zip_safe=False,

    # -- self - tests --------------------------------------------------------
    #test_suite='nose.collector',
    #test_suite='tests.test_runner',
    #test_loader='tests.test_runner:run_suite',
    tests_require=TEST_REQUIREMENTS,

    # -- script entry points -----------------------------------------------
    entry_points="""\
          [paste.app_factory]
          main = magpie.magpiectl:main
          [console_scripts]
          """,
)
