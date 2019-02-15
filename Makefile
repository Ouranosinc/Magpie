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
DOCKER_REPO := pavics/magpie

# conda
CONDA_ENV ?= $(APP_NAME)
CONDA_HOME ?= $(HOME)/conda
CONDA_ENVS_DIR ?= $(CONDA_HOME)/envs
CONDA_ENV_PATH := $(CONDA_ENVS_DIR)/$(CONDA_ENV)
DOWNLOAD_CACHE ?= $(APP_ROOT)/downloads
PYTHON_VERSION ?= `python -c 'import sys; print(sys.version[:5])'`

# choose conda installer depending on your OS
CONDA_URL = https://repo.continuum.io/miniconda
OS_NAME := $(shell uname -s || echo "unknown")
ifeq "$(OS_NAME)" "Linux"
FN := Miniconda3-latest-Linux-x86_64.sh
else ifeq "$(OS_NAME)" "Darwin"
FN := Miniconda3-latest-MacOSX-x86_64.sh
else
FN := unknown
endif


.DEFAULT_GOAL := help

.PHONY: all
all: help

.PHONY: help
help:
	@echo "Please use \`make <target>' where <target> is one of:"
	@echo "  Cleaning:"
	@echo "    clean:           remove all build, test, coverage and Python artifacts"
	@echo "    clean-build:     remove build artifacts"
	@echo "    clean-docs: 	    remove doc artifacts"
	@echo "    clean-pyc:       remove Python file artifacts"
	@echo "    clean-test:      remove test and coverage artifacts"
	@echo "  Build and deploy:"
	@echo "    bump             bump version using version specified as user input"
	@echo "    bump-dry         bump version using version specified as user input (dry-run)"
	@echo "    bump-tag         bump version using version specified as user input, tags it and commits change in git"
	@echo "    dist:            package"
	@echo "    release:         package and upload a release"
	@echo "    docker-info:     tag version of docker image for build/push"
	@echo "    docker-build:    build docker image"
	@echo "    docker-push:     push built docker image"
	@echo "    version:         current version"
	@echo "  Install and run"
	@echo "    docs:            generate Sphinx HTML documentation, including API docs"
	@echo "    install:         install the package to the active Python's site-packages"
	@echo "    sysinstall:      install system dependencies and required installers/runners"
	@echo "    migrate:         run postgres database migration with alembic"
	@echo "    start:           start magpie instance with gunicorn"
	@echo "  Test and coverage"
	@echo "    coverage:        check code coverage and generate a report"
	@echo "    coverage-show:   check code coverage and generate a report served on a web interface"
	@echo "    lint:            check style with flake8"
	@echo "    test:            run tests quickly with the default Python"
	@echo "    test-local:      run only local tests with the default Python"
	@echo "    test-remote:     run only remote tests with the default Python"
	@echo "    test-tox:        run tests on every Python version with tox"

.PHONY: clean clean-build clean-pyc clean-test
clean: clean-build clean-pyc clean-test clean-docs

clean-build:
	@echo "Cleaning build artifacts..."
	rm -fr build/
	rm -fr dist/
	rm -fr downloads/
	rm -fr .eggs/
	find . -type d -name '*.egg-info' -exec rm -fr {} +
	find . -type f -name '*.egg' -exec rm -f {} +

clean-docs:
	@echo "Cleaning doc artifacts..."
	"$(MAKE)" -C "$(CUR_DIR)/docs" clean || true

clean-pyc:
	@echo "Cleaning Python artifacts..."
	find . -type f -name '*.pyc' -exec rm -f {} +
	find . -type f -name '*.pyo' -exec rm -f {} +
	find . -type f -name '*~' -exec rm -f {} +
	find . -type f -name '__pycache__' -exec rm -fr {} +

clean-test:
	@echo "Cleaning tests artifacts..."
	rm -fr .tox/
	rm -fr .pytest_cache/
	rm -f .coverage
	rm -f coverage.xml
	rm -fr "$(CUR_DIR)/coverage/"

.PHONY: lint
lint: install-dev
	@echo "Checking code style with flake8..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; flake8 magpie tests --ignore=E501,W291 || true'

.PHONY: test
test: install-dev install
	@echo "Running tests..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; python setup.py test'

.PHONY: test-local
test-local: install-dev install
	@echo "Running local tests..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; MAGPIE_TEST_REMOTE=false python setup.py test'

.PHONY: test-remote
test-remote: install-dev install
	@echo "Running remote tests..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; MAGPIE_TEST_LOCAL=false python setup.py test'

.PHONY: test-tox
test-tox: install-dev install
	@echo "Running tests with tox..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; tox'

.PHONY: coverage
coverage: install-dev install
	@echo "Running coverage analysis..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; coverage run --source magpie setup.py test || true'
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; coverage xml -i'
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; coverage report -m'

.PHONY: coverage-show
coverage-show: coverage
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; coverage html -d coverage'
	"$(BROWSER)" "$(CUR_DIR)/coverage/index.html"

.PHONY: migrate
migrate: install conda-env
	@echo "Running database migration..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; \
		alembic -c "$(CUR_DIR)/magpie/alembic/alembic.ini" upgrade head'

.PHONY: docs
docs: install-dev
	@echo "Building docs..."
	rm -f $(CUR_DIR)/docs/magpie.rst
	rm -f $(CUR_DIR)/docs/modules.rst
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; \
		sphinx-apidoc -o "$(CUR_DIR)/docs/" "$(CUR_DIR)/magpie"; \
		"$(MAKE)" -C "$(CUR_DIR)/docs" clean; \
		"$(MAKE)" -C "$(CUR_DIR)/docs" html;'
	"$(BROWSER)" "$(CUR_DIR)/docs/_build/html/index.html"'

.PHONY: serve-docs
serve-docs: docs install-dev
	@echo "Serving docs..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; \
		watchmedo shell-command -p '*.rst' -c '$(MAKE) -C docs html' -R -D .'

.PHONY: release
release: clean install
	@echo "Creating release..."
	python setup.py sdist upload
	python setup.py bdist_wheel upload

.PHONY: bump
bump:
	$(shell bash -c 'read -p "Version: " VERSION_PART; \
		source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; \
		test -f "$(CONDA_ENV_PATH)/bin/bumpversion" || pip install bumpversion; \
		"$(CONDA_ENV_PATH)/bin/bumpversion" --config-file "$(CUR_DIR)/.bumpversion.cfg" \
		--verbose --allow-dirty --no-tag --new-version $$VERSION_PART patch;')

.PHONY: bump-dry
bump-dry:
	$(shell bash -c 'read -p "Version: " VERSION_PART; \
		source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; \
		test -f "$(CONDA_ENV_PATH)/bin/bumpversion" || pip install bumpversion; \
		"$(CONDA_ENV_PATH)/bin/bumpversion" --config-file "$(CUR_DIR)/.bumpversion.cfg" \
		--verbose --allow-dirty --dry-run --tag --tag-name "{new_version}" --new-version $$VERSION_PART patch;')

.PHONY: bump-tag
bump-tag:
	$(shell bash -c 'read -p "Version: " VERSION_PART; \
		source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; \
		test -f $(CONDA_ENV_PATH)/bin/bumpversion || pip install bumpversion; \
		"$(CONDA_ENV_PATH)/bin/bumpversion" --config-file "$(CUR_DIR)/.bumpversion.cfg" \
		--verbose --allow-dirty --tag --tag-name "{new_version}" --new-version $$VERSION_PART patch;')

.PHONY: dist
dist: clean conda-env
	@echo "Creating distribution..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; python setup.py sdist'
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; python setup.py bdist_wheel'
	ls -l dist

.PHONY: sysinstall
sysinstall: clean conda-env
	@echo "Installing system dependencies..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; pip install --upgrade pip setuptools'
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; pip install gunicorn'

.PHONY: install
install: sysinstall
	@echo "Installing Magpie..."
	# TODO: remove when merged
	# --- ensure fix is applied
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; \
		pip install --force-reinstall "https://github.com/fmigneault/authomatic/archive/httplib-port.zip#egg=Authomatic"'
	# ---
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; pip install --upgrade "$(CUR_DIR)"'

.PHONY: install-dev
install-dev: conda-env
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; pip install -r "$(CUR_DIR)/requirements-dev.txt"'
	@echo "Successfully installed dev requirements."

.PHONY: cron
cron:
	@echo "Starting Cron service..."
	cron

.PHONY: start
start: install
	@echo "Starting Magpie..."
	@bash -c 'source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)"; \
		exec gunicorn -b 0.0.0.0:2001 --paste "$(CUR_DIR)/magpie/magpie.ini" --workers 10 --preload &'

.PHONY: version
version:
	@echo "Mapie version:"
	@python -c 'from magpie.__meta__ import __version__; print(__version__)'

## Docker targets

.PHONY: docker-info
docker-info:
	@echo "Will be built, tagged and pushed as:"
	@echo "$(DOCKER_REPO):`python -c 'from magpie.__meta__ import __version__; print(__version__)'`"

.PHONY: docker-build
docker-build:
	@bash -c "docker build $(CUR_DIR) \
		-t $(DOCKER_REPO):`python -c 'from magpie.__meta__ import __version__; print(__version__)'`"

.PHONY: docker-push
docker-push: docker-build
	@bash -c "docker push $(DOCKER_REPO):`python -c 'from magpie.__meta__ import __version__; print(__version__)'`"

## Conda targets

.PHONY: conda-base
conda-base:
	@test -f "$(CONDA_HOME)/bin/conda" || test -d "$(DOWNLOAD_CACHE)" || \
		(echo "Creating download directory: $(DOWNLOAD_CACHE)" && mkdir -p "$(DOWNLOAD_CACHE)")
	@test -f "$(CONDA_HOME)/bin/conda" || test -f "$(DOWNLOAD_CACHE)/$(FN)" || \
		(echo "Fetching conda distribution from: $(CONDA_URL)/$(FN)" && \
		 curl "$(CONDA_URL)/$(FN)" --insecure --output "$(DOWNLOAD_CACHE)/$(FN)")
	@test -f "$(CONDA_HOME)/bin/conda" || \
		(bash "$(DOWNLOAD_CACHE)/$(FN)" -b -u -p "$(CONDA_HOME)" && \
		 echo "Make sure to add '$(CONDA_HOME)/bin' to your PATH variable in '~/.bashrc'.")

.PHONY: conda-cfg
conda_config: conda-base
	@echo "Updating conda configuration..."
	@"$(CONDA_HOME)/bin/conda" config --set ssl_verify true
	@"$(CONDA_HOME)/bin/conda" config --set use_pip true
	@"$(CONDA_HOME)/bin/conda" config --set channel_priority true
	@"$(CONDA_HOME)/bin/conda" config --set auto_update_conda false
	@"$(CONDA_HOME)/bin/conda" config --add channels defaults

# the conda-env target's dependency on conda-cfg above was removed, will add back later if needed

.PHONY: conda-env
conda-env: conda-base
	@test -d "$(CONDA_ENV_PATH)" || \
		(echo "Creating conda environment at '$(CONDA_ENV_PATH)'..." && \
		 "$(CONDA_HOME)/bin/conda" create -y -n "$(CONDA_ENV)" python=$(PYTHON_VERSION))
