.PHONY: clean-pyc clean-build docs clean
define BROWSER_PYSCRIPT
import os, webbrowser, sys
try:
	from urllib import pathname2url
except:
	from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT
BROWSER := python -c "$$BROWSER_PYSCRIPT"

# Application
CUR_DIR := $(abspath $(lastword $(MAKEFILE_LIST))/..)
APP_ROOT := $(CUR_DIR)
APP_NAME := $(shell basename $(APP_ROOT))

.PHONY: all
all: help

help:
	@echo "clean - remove all build, test, coverage and Python artifacts"
	@echo "clean-build - remove build artifacts"
	@echo "clean-pyc - remove Python file artifacts"
	@echo "clean-test - remove test and coverage artifacts"
	@echo "conda-create - create conda magpie environment"
	@echo "coverage - check code coverage quickly with the default Python"
	@echo "dist - package"
	@echo "docs - generate Sphinx HTML documentation, including API docs"
	@echo "install - install the package to the active Python's site-packages"
	@echo "lint - check style with flake8"
	@echo "migrate - run postgres database migration with alembic"
	@echo "release - package and upload a release"
	@echo "start - start magpie instance with gunicorn"
	@echo "test - run tests quickly with the default Python"
	@echo "test-local - run only local tests with the default Python"
	@echo "test-remote - run only remote tests with the default Python"
	@echo "test-all - run tests on every Python version with tox"

clean: clean-build clean-pyc clean-test

clean-build:
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -type f -name '*.egg-info' -exec rm -fr {} +
	find . -type f -name '*.egg' -exec rm -f {} +

clean-pyc:
	find . -type f -name '*.pyc' -exec rm -f {} +
	find . -type f -name '*.pyo' -exec rm -f {} +
	find . -type f -name '*~' -exec rm -f {} +
	find . -type f -name '__pycache__' -exec rm -fr {} +

clean-test:
	rm -fr .tox/
	rm -f .coverage
	rm -fr coverage/

lint:
	flake8 magpie tests

test: install
	python setup.py test

test-local: install
	MAGPIE_TEST_REMOTE=false python setup.py test

test-remote: install
	MAGPIE_TEST_LOCAL=false python setup.py test

test-all:
	tox

coverage:
	coverage run --source magpie setup.py test
	coverage report -m
	coverage html -d coverage
	$(BROWSER) coverage/index.html

migrate: install
	alembic -c $(CUR_DIR)/magpie/alembic/alembic.ini upgrade head

docs:
	@echo $(CUR_DIR)
	rm -f $(CUR_DIR)/docs/magpie.rst
	rm -f $(CUR_DIR)/docs/modules.rst
	sphinx-apidoc -o $(CUR_DIR)/docs/ $(CUR_DIR)/magpie
	$(MAKE) -C $(CUR_DIR)/docs clean
	$(MAKE) -C $(CUR_DIR)/docs html
	$(BROWSER) $(CUR_DIR)/docs/_build/html/index.html

servedocs: docs
	watchmedo shell-command -p '*.rst' -c '$(MAKE) -C docs html' -R -D .

release: clean
	python setup.py sdist upload
	python setup.py bdist_wheel upload

dist: clean
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

install: clean
	python setup.py install

start: install
	@echo "Starting Magpie"
	exec gunicorn -b 0.0.0.0:2001 --paste "$(CUR_DIR)/magpie/magpie.ini" --workers 10 --preload
