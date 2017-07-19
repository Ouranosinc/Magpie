#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import find_packages
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from magpie.__meta__ import __version__, __author__, __email__

with open('README.rst') as readme_file:
    README = readme_file.read()

with open('HISTORY.rst') as history_file:
    HISTORY = history_file.read().replace('.. :changelog:', '')

REQUIREMENTS = [
    # TODO: put package requirements here
]

TEST_REQUIREMENTS = [
    'nose',
    # TODO: put package test requirements here
]

setup(
    # -- meta information --------------------------------------------------
    name='magpie',
    version=__version__,
    description="Magpie is a service for AuthN and AuthZ based on Ziggurat-Foundations",
    long_description=README + '\n\n' + HISTORY,
    author=__author__,
    author_email=__email__,
    url='https://github.com/fderue/magpie',
    platforms=['linux_x86_64'],
    license="ISCL",
    keywords='magpie',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],

    # -- Package structure -------------------------------------------------
    #packages=[
    #    'magpie',
    #],
    packages=find_packages(),
    package_dir={'magpie':
                 'magpie'},
    include_package_data=True,
    install_requires=REQUIREMENTS,
    zip_safe=False,

    # -- self - tests --------------------------------------------------------
    test_suite='tests',
    tests_require=TEST_REQUIREMENTS,

    # -- script entry points -----------------------------------------------
    entry_points="""\
          [paste.app_factory]
          main = magpie:main
          [console_scripts]
          """,
)
