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
MAGPIE_ROOT    := $(abspath $(lastword $(MAKEFILE_LIST))/..)
MAGPIE_NAME    := $(shell basename $(MAGPIE_ROOT))
MAGPIE_VERSION ?= 1.7.1
MAGPIE_INI     ?= $(MAGPIE_ROOT)/config/magpie.ini

# conda
CONDA_ENV      ?= $(MAGPIE_NAME)
CONDA_HOME     ?= $(HOME)/.conda
CONDA_ENVS_DIR ?= $(CONDA_HOME)/envs
CONDA_ENV_PATH := $(CONDA_ENVS_DIR)/$(CONDA_ENV)
DOWNLOAD_CACHE ?= $(MAGPIE_ROOT)/downloads
PYTHON_VERSION ?= `python -c 'import platform; print(platform.python_version())'`

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

CONDA_CMD := source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)";

# docker
MAGPIE_DOCKER_REPO   := pavics/magpie
MAGPIE_DOCKER_TAG    := $(MAGPIE_DOCKER_REPO):$(MAGPIE_VERSION)
TWITCHER_DOCKER_REPO := pavics/twitcher
TWITCHER_DOCKER_TAG  := $(TWITCHER_DOCKER_REPO):magpie-$(MAGPIE_VERSION)

.DEFAULT_GOAL := help

.PHONY: all
all: help

# Auto documented help from target comments
#	https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help
help:
	@echo "magpie help"
	@echo "Please use 'make <target>' where <target> is one of:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-24s\033[0m %s\n", $$1, $$2}'

## clean targets

.PHONY: clean clean-build clean-pyc clean-test
clean: clean-build clean-pyc clean-test clean-docs	## remove all build, test, coverage and Python artifacts

clean-build:	## remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -fr build/
	rm -fr dist/
	rm -fr downloads/
	rm -fr .eggs/
	find . -type d -name '*.egg-info' -exec rm -fr {} +
	find . -type f -name '*.egg' -exec rm -f {} +

clean-docs:		## remove doc artifacts
	@echo "Cleaning doc artifacts..."
	"$(MAKE)" -C "$(MAGPIE_ROOT)/docs" clean || true

clean-pyc:		## remove Python file artifacts
	@echo "Cleaning Python artifacts..."
	find . -type f -name '*.pyc' -exec rm -f {} +
	find . -type f -name '*.pyo' -exec rm -f {} +
	find . -type f -name '*~' -exec rm -f {} +
	find . -type f -name '__pycache__' -exec rm -fr {} +

clean-test:		## remove test and coverage artifacts
	@echo "Cleaning tests artifacts..."
	rm -fr .tox/
	rm -fr .pytest_cache/
	rm -f .coverage
	rm -f coverage.xml
	rm -fr "$(MAGPIE_ROOT)/coverage/"

.PHONY: lint
lint: install-dev	## check PEP8 code style
	@echo "Checking PEP8 code style problems..."
	@bash -c '$(CONDA_CMD) \
		flake8 && \
		docformatter \
			--pre-summary-newline \
			--wrap-descriptions 120 \
			--wrap-summaries 120 \
			--make-summary-multi-line \
			-c -r $(MAGPIE_ROOT)'

.PHONY: lint-fix
lint-fix: install-dev	## automatically fix PEP8 code style problems
	@echo "Fixing PEP8 code style problems..."
	@bash -c '$(CONDA_CMD) \
		autopep8 -v -j 0 -i -r $(MAGPIE_ROOT) && \
		docformatter \
			--pre-summary-newline \
			--wrap-descriptions 120 \
			--wrap-summaries 120 \
			--make-summary-multi-line \
			-i -r $(MAGPIE_ROOT)'

.PHONY: test
test: install-dev install			## run tests quickly with the default Python
	@echo "Running tests..."
	bash -c '$(CONDA_CMD) pytest tests -vv --junitxml "$(MAGPIE_ROOT)/tests/results.xml"'

.PHONY: test-local
test-local: install-dev install		## run only local tests with the default Python
	@echo "Running local tests..."
	bash -c '$(CONDA_CMD) pytest tests -vv -m "not remote" --junitxml "$(MAGPIE_ROOT)/tests/results.xml"'

.PHONY: test-remote
test-remote: install-dev install	## run only remote tests with the default Python
	@echo "Running remote tests..."
	bash -c '$(CONDA_CMD) pytest tests -vv -m "not local" --junitxml "$(MAGPIE_ROOT)/tests/results.xml"'

COVERAGE_FILE := $(MAGPIE_ROOT)/.coverage
COVERAGE_HTML := $(MAGPIE_ROOT)/coverage/index.html
$(COVERAGE_FILE):
	@echo "Running coverage analysis..."
	@bash -c '$(CONDA_CMD) coverage run --source "$(MAGPIE_ROOT)/magpie" \
		"$(CONDA_ENV_PATH)/bin/pytest" tests -m "not remote" || true'
	@bash -c '$(CONDA_CMD) coverage xml -i'
	@bash -c '$(CONDA_CMD) coverage report -m'
	@bash -c '$(CONDA_CMD) coverage html -d "$(MAGPIE_ROOT)/coverage"'
	@-echo "Coverage report available: file://$(COVERAGE_HTML)"

.PHONY: coverage
coverage: install-dev install $(COVERAGE_FILE)	## check code coverage and generate an analysis report

.PHONY: coverage-show
coverage-show: $(COVERAGE_HTML)		## display HTML webpage of generated coverage report (run coverage if missing)
	@-test -f "$(COVERAGE_HTML)" || $(MAKE) -C "$(MAGPIE_ROOT)" coverage
	$(BROWSER) "$(COVERAGE_HTML)"

.PHONY: migrate
migrate: install conda-env	## run postgres database migration with alembic
	@echo "Running database migration..."
	@bash -c '$(CONDA_CMD) alembic -c "$(MAGPIE_INI)" upgrade head'

DOC_LOCATION := $(MAGPIE_ROOT)/docs/_build/html/index.html
$(DOC_LOCATION):
	@echo "Building docs..."
	rm -f $(MAGPIE_ROOT)/docs/magpie.rst
	rm -f $(MAGPIE_ROOT)/docs/modules.rst
	@bash -c '$(CONDA_CMD) \
		sphinx-apidoc -o "$(MAGPIE_ROOT)/docs/" "$(MAGPIE_ROOT)/magpie"; \
		"$(MAKE)" -C "$(MAGPIE_ROOT)/docs" clean; \
		"$(MAKE)" -C "$(MAGPIE_ROOT)/docs" html;'
	@-echo "Documentation available: file://$(DOC_LOCATION)"

.PHONY: docs
docs: install-dev clean-docs $(DOC_LOCATION)	## generate Sphinx HTML documentation, including API docs

.PHONY: docs-show
docs-show: $(DOC_LOCATION)	## display HTML webpage of generated documentation (build docs if missing)
	@-test -f "$(DOC_LOCATION)" || $(MAKE) -C "$(MAGPIE_ROOT)" docs
	$(BROWSER) "$(DOC_LOCATION)"

# Bumpversion 'dry' config
# if 'dry' is specified as target, any bumpversion call using 'BUMP_XARGS' will not apply changes
BUMP_XARGS ?= --verbose --allow-dirty
ifeq ($(filter dry, $(MAKECMDGOALS)), dry)
	BUMP_XARGS := $(BUMP_XARGS) --dry-run
endif

.PHONY: dry
dry: setup.cfg	## run 'bump' target without applying changes (dry-run)
ifeq ($(findstring bump, $(MAKECMDGOALS)),)
	$(error Target 'dry' must be combined with a 'bump' target)
endif

.PHONY: bump
bump:	## bump version using VERSION specified as user input
	@-echo "Updating package version ..."
	@[ "${VERSION}" ] || ( echo ">> 'VERSION' is not set"; exit 1 )
	@-bash -c '$(CONDA_CMD) test -f "$(CONDA_ENV_PATH)/bin/bump2version || pip install bump2version'
	@-bash -c '$(CONDA_CMD) bump2version $(BUMP_XARGS) --new-version "${VERSION}" patch;'

.PHONY: dist
dist: clean conda-env	## package for distribution
	@echo "Creating distribution..."
	@bash -c '$(CONDA_CMD) python setup.py sdist'
	@bash -c '$(CONDA_CMD) python setup.py bdist_wheel'
	ls -l dist

.PHONY: install-sys
install-sys: clean conda-env	## install system dependencies and required installers/runners
	@echo "Installing system dependencies..."
	@bash -c '$(CONDA_CMD) pip install --upgrade pip setuptools'
	@bash -c '$(CONDA_CMD) pip install gunicorn'

.PHONY: install
install: install-sys	## install the package to the active Python's site-packages
	@echo "Installing Magpie..."
	# TODO: remove when merged
	# --- ensure fix is applied
	@bash -c '$(CONDA_CMD) \
		pip install --force-reinstall "https://github.com/fmigneault/authomatic/archive/httplib-port.zip#egg=Authomatic"'
	# ---
	@bash -c '$(CONDA_CMD) python setup.py install_egg_info'
	@bash -c '$(CONDA_CMD) pip install --upgrade -e "$(MAGPIE_ROOT)" --no-cache'

.PHONY: install-dev
install-dev: conda-env	## install package requirements for development and testing
	@bash -c '$(CONDA_CMD) pip install -r "$(MAGPIE_ROOT)/requirements-dev.txt"'
	@echo "Successfully installed dev requirements."

.PHONY: cron
cron:
	@echo "Starting Cron service..."
	cron

.PHONY: start
start: install	## start magpie instance with gunicorn
	@echo "Starting Magpie..."
	@bash -c '$(CONDA_CMD) exec gunicorn -b 0.0.0.0:2001 --paste "$(MAGPIE_INI)" --workers 10 --preload &'

.PHONY: version
version:	## display current version
	@-echo "Mapie version: $(MAGPIE_VERSION)"

## Docker targets

.PHONY: docker-info
docker-info:	## tag version of docker image for build/push
	@echo "Magpie image will be built, tagged and pushed as:"
	@echo "$(MAGPIE_DOCKER_TAG)"
	@echo "MagpieAdapter image will be built, tagged and pushed as:"
	@echo "$(TWITCHER_DOCKER_TAG)"

.PHONY: docker-build-adapter
docker-build-adapter:	## build only docker image for Magpie application
	docker build "$(MAGPIE_ROOT)" -t "$(TWITCHER_DOCKER_TAG)" -f Dockerfile.adapter

.PHONY: docker-build-magpie
docker-build-magpie:	## build only docker image of MagpieAdapter for Twitcher
	docker build "$(MAGPIE_ROOT)" -t "$(MAGPIE_DOCKER_TAG)"

.PHONY: docker-build
docker-build: docker-build-magpie docker-build-adapter	## build docker images for Magpie application and MagpieAdapter for Twitcher

.PHONY: docker-push-adapter
docker-push-adapter: docker-build-adapter	## push only built docker image of MagpieAdapter for Twitcher
	docker push "$(TWITCHER_DOCKER_TAG)"

.PHONY: docker-push-magpie
docker-push-magpie: docker-build-magpie		## push only built docker image for Magpie application
	docker push "$(MAGPIE_DOCKER_TAG)"

.PHONY: docker-push
docker-push: docker-push-magpie docker-push-adapter	 ## push built docker images for Magpie application and MagpieAdapter for Twitcher

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
