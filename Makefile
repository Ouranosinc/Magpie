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

# Included custom configs change the value of MAKEFILE_LIST
# Extract the required reference beforehand so we can use it for help target
MAKEFILE_NAME := $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))
# Include custom config if it is available
-include Makefile.config

# Application
APP_ROOT    := $(abspath $(lastword $(MAKEFILE_NAME))/..)
APP_NAME    := magpie
APP_VERSION ?= 1.7.5
APP_INI     ?= $(APP_ROOT)/config/$(APP_NAME).ini

# conda
CONDA_ENV      ?= $(APP_NAME)
CONDA_HOME     ?= $(HOME)/.conda
CONDA_ENVS_DIR ?= $(CONDA_HOME)/envs
CONDA_ENV_PATH := $(CONDA_ENVS_DIR)/$(CONDA_ENV)
CONDA_BIN      := $(CONDA_HOME)/bin/conda
CONDA_ENV_REAL_TARGET_PATH := $(realpath $(CONDA_ENV_PATH))
CONDA_ENV_REAL_ACTIVE_PATH := $(realpath ${CONDA_PREFIX})
ifeq "$(CONDA_ENV_REAL_ACTIVE_PATH)" "$(CONDA_ENV_REAL_TARGET_PATH)"
	CONDA_CMD :=
	CONDA_ENV_MODE := [using active environment]
else
	CONDA_CMD := source "$(CONDA_HOME)/bin/activate" "$(CONDA_ENV)";
	CONDA_ENV_MODE := [will activate environment]
endif
PYTHON_VERSION ?= `python -c 'import platform; print(platform.python_version())'`

DOWNLOAD_CACHE ?= $(APP_ROOT)/downloads
REPORTS_DIR ?= $(APP_ROOT)/reports

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

# docker
MAGPIE_DOCKER_REPO   := pavics/magpie
MAGPIE_DOCKER_TAG    := $(MAGPIE_DOCKER_REPO):$(APP_VERSION)
MAGPIE_LATEST_TAG	 := $(MAGPIE_DOCKER_REPO):latest
TWITCHER_DOCKER_REPO := pavics/twitcher
TWITCHER_DOCKER_TAG  := $(TWITCHER_DOCKER_REPO):magpie-$(APP_VERSION)

.DEFAULT_GOAL := help

## --- Informative targets --- ##

.PHONY: all
all: help

# Auto documented help targets & sections from comments
#	- detects lines marked by double octothorpe (#), then applies the corresponding target/section markup
#   - target comments must be defined after their dependencies (if any)
#	- section comments must have at least a double dash (-)
#
# 	Original Reference:
#		https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
# 	Formats:
#		https://misc.flogisoft.com/bash/tip_colors_and_formatting
_SECTION := \033[34m
_TARGET  := \033[36m
_NORMAL  := \033[0m
.PHONY: help
# note: use "\#\#" to escape results that would self-match in this target's search definition
help:	## print this help message (default)
	@echo "$(_SECTION)=== $(APP_NAME) help ===$(_NORMAL)"
	@echo "Please use 'make <target>' where <target> is one of:"
#	@grep -E '^[a-zA-Z_-]+:.*?\#\# .*$$' $(MAKEFILE_LIST) \
#		| awk 'BEGIN {FS = ":.*?\#\# "}; {printf "    $(_TARGET)%-24s$(_NORMAL) %s\n", $$1, $$2}'
	@grep -E '\#\#.*$$' "$(APP_ROOT)/$(MAKEFILE_NAME)" \
		| awk ' BEGIN {FS = "(:|\-\-\-)+.*?\#\# "}; \
			/\--/ {printf "$(_SECTION)%s$(_NORMAL)\n", $$1;} \
			/:/   {printf "    $(_TARGET)%-24s$(_NORMAL) %s\n", $$1, $$2} \
		'

.PHONY: version
version:	## display current version
	@-echo "$(APP_NAME) version: $(APP_VERSION)"

.PHONY: info
info:		## display make information
	@echo "Informations about your make execution:"
	@echo "  OS_NAME             $(OS_NAME)"
	@echo "  CPU_ARCH            $(CPU_ARCH)"
	@echo "  Conda Home          $(CONDA_HOME)"
	@echo "  Conda Environment   $(CONDA_ENV)"
	@echo "  Conda Prefix        $(CONDA_ENV_PATH)"
	@echo "  Conda Binary        $(CONDA_BIN)"
	@echo "  Conda Actication    $(CONDA_ENV_MODE)"
	@echo "  Conda Command       $(CONDA_CMD)"
	@echo "  APP_NAME            $(APP_NAME)"
	@echo "  APP_ROOT            $(APP_ROOT)"
	@echo "  DOWNLOAD_CACHE      $(DOWNLOAD_CACHE)"
	@echo "  DOCKER_REPO         $(DOCKER_REPO)"

## --- Cleanup targets --- ##

.PHONY: clean
clean: clean-all	## alias for 'clean-all' target

.PHONY: clean-all
clean-all: clean-build clean-pyc clean-test clean-docs	## remove all artifacts

.PHONY: clean-build
clean-build:	## remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -fr build/
	rm -fr dist/
	rm -fr downloads/
	rm -fr .eggs/
	find . -type d -name '*.egg-info' -exec rm -fr {} +
	find . -type f -name '*.egg' -exec rm -f {} +

.PHONY: clean-docs
clean-docs:		## remove doc artifacts
	@echo "Cleaning doc artifacts..."
	"$(MAKE)" -C "$(APP_ROOT)/docs" clean || true

.PHONY: clean-pyc
clean-pyc:		## remove Python file artifacts
	@echo "Cleaning Python artifacts..."
	find . -type f -name '*.pyc' -exec rm -f {} +
	find . -type f -name '*.pyo' -exec rm -f {} +
	find . -type f -name '*~' -exec rm -f {} +
	find . -type f -name '__pycache__' -exec rm -fr {} +

.PHONY: clean-test
clean-test:		## remove test and coverage artifacts
	@echo "Cleaning tests artifacts..."
	@-rm -fr .tox/
	@-rm -fr .pytest_cache/
	@-rm -f .coverage*
	@-rm -f coverage.*
	@-rm -fr "$(APP_ROOT)/coverage/"
	@-rm -fr "$(REPORTS_DIR)"

.PHONY: clean-docker
clean-docker: docker-clean	## alias for 'docker-clean' target

## --- Database targets --- ##

.PHONY: migrate
migrate: install conda-env	## run postgres database migration with alembic
	@echo "Running database migration..."
	@bash -c '$(CONDA_CMD) alembic -c "$(APP_INI)" upgrade head'

## --- Documentation targets --- ##

DOC_LOCATION := $(APP_ROOT)/docs/_build/html/index.html
$(DOC_LOCATION):
	@echo "Building docs..."
	rm -f $(APP_ROOT)/docs/$(APP_NAME).rst
	rm -f $(APP_ROOT)/docs/modules.rst
	@bash -c '$(CONDA_CMD) \
		sphinx-apidoc -o "$(APP_ROOT)/docs/" "$(APP_ROOT)/$(APP_NAME)"; \
		"$(MAKE)" -C "$(APP_ROOT)/docs" clean; \
		"$(MAKE)" -C "$(APP_ROOT)/docs" html;'
	@-echo "Documentation available: file://$(DOC_LOCATION)"

.PHONY: docs
docs: install-dev clean-docs $(DOC_LOCATION)	## generate Sphinx HTML documentation, including API docs

.PHONY: docs-show
docs-show: $(DOC_LOCATION)	## display HTML webpage of generated documentation (build docs if missing)
	@-test -f "$(DOC_LOCATION)" || $(MAKE) -C "$(APP_ROOT)" docs
	$(BROWSER) "$(DOC_LOCATION)"

## --- Versionning targets --- ##

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

## --- Installation targets --- ##

.PHONY: dist
dist: clean conda-env	## package for distribution
	@echo "Creating distribution..."
	@bash -c '$(CONDA_CMD) python setup.py sdist'
	@bash -c '$(CONDA_CMD) python setup.py bdist_wheel'
	ls -l dist

.PHONY: install
install: install-all	## alias for 'install-all' target

.PHONY: install-all		## install every dependency and package definition
install-all: install-sys install-pkg install-dev

.PHONY: install-sys
install-sys: clean conda-env	## install system dependencies and required installers/runners
	@echo "Installing system dependencies..."
	@bash -c '$(CONDA_CMD) pip install --upgrade pip setuptools'
	@bash -c '$(CONDA_CMD) pip install gunicorn'

.PHONY: install-pkg
install-pkg: install-sys	## install the package to the active Python's site-packages
	@echo "Installing Magpie..."
	# TODO: remove when merged
	# --- ensure fix is applied
	@bash -c '$(CONDA_CMD) \
		pip install --force-reinstall "https://github.com/fmigneault/authomatic/archive/httplib-port.zip#egg=Authomatic"'
	# ---
	@bash -c '$(CONDA_CMD) python setup.py install_egg_info'
	@bash -c '$(CONDA_CMD) pip install --upgrade -e "$(APP_ROOT)" --no-cache'

.PHONY: install-dev
install-dev: conda-env	## install package requirements for development and testing
	@bash -c '$(CONDA_CMD) pip install -r "$(APP_ROOT)/requirements-dev.txt"'
	@echo "Successfully installed dev requirements."

## --- Launchers targets --- ##

.PHONY: cron
cron:
	@echo "Starting Cron service..."
	cron

.PHONY: start
start: install	## start application instance(s) with gunicorn
	@echo "Starting $(APP_NAME)..."
	@bash -c '$(CONDA_CMD) exec gunicorn -b 0.0.0.0:2001 --paste "$(APP_INI)" --preload &'

.PHONY: stop
stop: 		## kill application instance(s) started with gunicorn
	@lsof -t -i :2001 | xargs kill

.PHONY: stat
stat: 		## display processes with PID(s) of gunicorn instance(s) running the application
	@lsof -i :2001 || echo "No instance running"

## --- Docker targets --- ##

.PHONY: docker-info
docker-info:	## tag version of docker image for build/push
	@echo "Magpie image will be built, tagged and pushed as:"
	@echo "$(MAGPIE_DOCKER_TAG)"
	@echo "MagpieAdapter image will be built, tagged and pushed as:"
	@echo "$(TWITCHER_DOCKER_TAG)"

.PHONY: docker-build-adapter
docker-build-adapter:	## build only docker image for Magpie application
	docker build "$(APP_ROOT)" -t "$(TWITCHER_DOCKER_TAG)" -f Dockerfile.adapter

.PHONY: docker-build-magpie
docker-build-magpie:	## build only docker image of MagpieAdapter for Twitcher
	docker build "$(APP_ROOT)" -t "$(MAGPIE_LATEST_TAG)"
	docker tag "$(MAGPIE_LATEST_TAG)" "$(MAGPIE_DOCKER_TAG)"

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

DOCKER_TEST_COMPOSES := -f "$(APP_ROOT)/ci/docker-compose.smoke-test.yml"
.PHONY: docker-test
docker-test: docker-build-magpie	## execute a smoke test of the built image for Magpie application (validate that it boots)
	@echo "Smoke test of built application docker image"
	docker-compose $(DOCKER_TEST_COMPOSES) up -d
	sleep 5
	curl localhost:2001 | grep "Magpie Administration"
	docker-compose $(DOCKER_TEST_COMPOSES) stop

.PHONY: docker-clean
docker-clean: 	## remove any leftover images from docker target operations
	docker rmi $(docker images -f "reference=$(MAGPIE_DOCKER_REPO)" -q)
	docker-compose $(DOCKER_TEST_COMPOSES) down

## --- Statoc code check targets ---

.PHONY: mkdir-reports
mkdir-reports:
	@mkdir -p "$(REPORTS_DIR)"

.PHONY: check
check: check-all	## alias for 'check-all' target

.PHONY: check-all
check-all: clean-test check-pep8 check-lint check-security check-docs check-links	## run every code style checks

.PHONY: check-pep8
check-pep8: mkdir-reports install-dev		## run PEP8 code style checks
	@echo "Running pep8 code style checks..."
	@-rm -fr "$(REPORTS_DIR)/check-pep8.txt"
	@bash -c '$(CONDA_CMD) \
		flake8 --config="$(APP_ROOT)/setup.cfg" --output-file="$(REPORTS_DIR)/check-pep8.txt" --tee'

.PHONY: check-lint
check-lint: mkdir-reports install-dev		## run linting code style checks
	@echo "Running linting code style checks..."
	@-rm -fr "$(REPORTS_DIR)/check-lint.txt"
	@bash -c '$(CONDA_CMD) \
		pylint \
			--load-plugins pylint_quotes \
			--rcfile="$(APP_ROOT)/.pylintrc" \
			--reports y \
			"$(APP_ROOT)/$(APP_NAME)" "$(APP_ROOT)/tests" \
		1> >(tee "$(REPORTS_DIR)/check-lint.txt")'

.PHONY: check-security
check-security: mkdir-reports install-dev	## run security code checks
	@echo "Running security code checks..."
	@-rm -fr "$(REPORTS_DIR)/check-security.txt"
	@bash -c '$(CONDA_CMD) \
		bandit -v --ini "$(APP_ROOT)/setup.cfg" -r \
		1> >(tee "$(REPORTS_DIR)/check-security.txt")'

.PHONY: check-docs
check-docs: check-doc8 check-docf	## run every code documentation checks

.PHONY: check-doc8
check-doc8:	mkdir-reports install-dev		## run PEP8 documentation style checks
	@echo "Running PEP8 doc style checks..."
	@-rm -fr "$(REPORTS_DIR)/check-doc8.txt"
	@bash -c '$(CONDA_CMD) \
		doc8 --config "$(APP_ROOT)/setup.cfg" "$(APP_ROOT)/docs" \
		1> >(tee "$(REPORTS_DIR)/check-doc8.txt")'

# FIXME: move parameters to setup.cfg when implemented (https://github.com/myint/docformatter/issues/10)
.PHONY: check-docf
check-docf: mkdir-reports install-dev	## run PEP8 code documentation format checks
	@echo "Checking PEP8 doc formatting problems..."
	@-rm -fr "$(REPORTS_DIR)/check-docf.txt"
	@bash -c '$(CONDA_CMD) \
		docformatter \
			--pre-summary-newline \
			--wrap-descriptions 120 \
			--wrap-summaries 120 \
			--make-summary-multi-line \
			-c -r "$(APP_ROOT)" \
		1> >(tee "$(REPORTS_DIR)/check-docf.txt")'

.PHONY: check-links
check-links:		## check all external links in documentation for integrity
	@echo "Running link checks on docs..."
	@bash -c '$(CONDA_CMD) (MAKE) -C "$(APP_ROOT)/docs" linkcheck'

.PHONY: check-imports
check-imports:		## run imports code checks
	@echo "Running import checks..."
	@-rm -fr "$(REPORTS_DIR)/check-imports.txt"
	@bash -c '$(CONDA_CMD) \
	 	isort --check-only --diff --recursive $(APP_ROOT) \
		1> >(tee "$(REPORTS_DIR)/check-imports.txt")'

.PHONY: fix
fix: fix-all	## alias for 'fix-all' target

.PHONY: fix-all
fix-all: fix-imports fix-lint fix-docf	## fix all applicable code check corrections automatically

.PHONY: fix-imports
fix-imports: install-dev	## fix import code checks corrections automatically
	@echo "Fixing flagged import checks..."
	@-rm -fr "$(REPORTS_DIR)/fixed-imports.txt"
	@bash -c '$(CONDA_CMD) \
		isort --recursive $(APP_ROOT) \
		1> >(tee "$(REPORTS_DIR)/fixed-imports.txt")'

.PHONY: fix-lint
fix-lint: install-dev	## fix some PEP8 code style problems automatically
	@echo "Fixing PEP8 code style problems..."
	@-rm -fr "$(REPORTS_DIR)/fixed-lint.txt"
	@bash -c '$(CONDA_CMD) \
		autopep8 -v -j 0 -i -r $(APP_ROOT) \
		1> >(tee "$(REPORTS_DIR)/fixed-lint.txt")'

# FIXME: move parameters to setup.cfg when implemented (https://github.com/myint/docformatter/issues/10)
.PHONY: fix-docf
fix-docf: install-dev	## fix some PEP8 code documentation style problems automatically
	@echo "Fixing PEP8 code documentation problems..."
	@-rm -fr "$(REPORTS_DIR)/fixed-docf.txt"
	@bash -c '$(CONDA_CMD) \
		docformatter \
			--pre-summary-newline \
			--wrap-descriptions 120 \
			--wrap-summaries 120 \
			--make-summary-multi-line \
			-i -r $(APP_ROOT) \
		1> >(tee "$(REPORTS_DIR)/fixed-docf.txt")'

## --- Test targets --- ##

.PHONY: test
test: test-all	## alias for 'test-all' target

.PHONY: test-all
test-all: install-dev install		## run all tests combinations
	@echo "Running tests..."
	@bash -c '$(CONDA_CMD) pytest tests -vv --junitxml "$(APP_ROOT)/tests/results.xml"'

# note: use 'not remote' instead of 'local' to capture other low-level tests like 'utils' unittests
.PHONY: test-local
test-local: install-dev install		## run only local tests with the default Python
	@echo "Running local tests..."
	@bash -c '$(CONDA_CMD) pytest tests -vv -m "not remote" --junitxml "$(APP_ROOT)/tests/results.xml"'

.PHONY: test-remote
test-remote: install-dev install	## run only remote tests with the default Python
	@echo "Running remote tests..."
	@bash -c '$(CONDA_CMD) pytest tests -vv -m "remote" --junitxml "$(APP_ROOT)/tests/results.xml"'

.PHONY: test-docker
test-docker: docker-test			## alias for 'docker-test' target - WARNING: could build image if missing

# covereage file location cannot be changed
COVERAGE_FILE     := $(APP_ROOT)/.coverage
COVERAGE_HTML_DIR := $(REPORTS_DIR)/coverage
COVERAGE_HTML_IDX := $(COVERAGE_HTML_DIR)/index.html
$(COVERAGE_FILE):
	@echo "Running coverage analysis..."
	@bash -c '$(CONDA_CMD) coverage run --source "$(APP_ROOT)/$(APP_NAME)" \
		"$(CONDA_ENV_PATH)/bin/pytest" tests -m "not remote" || true'
	@bash -c '$(CONDA_CMD) coverage xml -i -o "$(REPORTS_DIR)/coverage.xml"'
	@bash -c '$(CONDA_CMD) coverage report -m'
	@bash -c '$(CONDA_CMD) coverage html -d "$(COVERAGE_HTML_DIR)"'
	@-echo "Coverage report available: file://$(COVERAGE_HTML_IDX)"

.PHONY: coverage
coverage: install-dev install $(COVERAGE_FILE)	## check code coverage and generate an analysis report

.PHONY: coverage-show
coverage-show: $(COVERAGE_HTML_IDX)		## display HTML webpage of generated coverage report (run coverage if missing)
	@-test -f "$(COVERAGE_HTML_IDX)" || $(MAKE) -C "$(APP_ROOT)" coverage
	$(BROWSER) "$(COVERAGE_HTML_IDX)"

## --- Conda setup targets --- ##

.PHONY: conda-base
conda-base:	 ## obtain a base distribution of conda if missing and required
	@test -f "$(CONDA_HOME)/bin/conda" || test -d "$(DOWNLOAD_CACHE)" || \
		(echo "Creating download directory: $(DOWNLOAD_CACHE)" && mkdir -p "$(DOWNLOAD_CACHE)")
	@test -f "$(CONDA_HOME)/bin/conda" || test -f "$(DOWNLOAD_CACHE)/$(FN)" || \
		(echo "Fetching conda distribution from: $(CONDA_URL)/$(FN)" && \
		 curl "$(CONDA_URL)/$(FN)" --insecure --output "$(DOWNLOAD_CACHE)/$(FN)")
	@test -f "$(CONDA_HOME)/bin/conda" || \
		(bash "$(DOWNLOAD_CACHE)/$(FN)" -b -u -p "$(CONDA_HOME)" && \
		 echo "Make sure to add '$(CONDA_HOME)/bin' to your PATH variable in '~/.bashrc'.")

.PHONY: conda-cfg
conda_config: conda-base	## update conda package configuration
	@echo "Updating conda configuration..."
	@"$(CONDA_HOME)/bin/conda" config --set ssl_verify true
	@"$(CONDA_HOME)/bin/conda" config --set use_pip true
	@"$(CONDA_HOME)/bin/conda" config --set channel_priority true
	@"$(CONDA_HOME)/bin/conda" config --set auto_update_conda false
	@"$(CONDA_HOME)/bin/conda" config --add channels defaults

# the conda-env target's dependency on conda-cfg above was removed, will add back later if needed

.PHONY: conda-env
conda-env: conda-base	## create conda environment if missing and required
	@test -d "$(CONDA_ENV_PATH)" || \
		(echo "Creating conda environment at '$(CONDA_ENV_PATH)'..." && \
		 "$(CONDA_HOME)/bin/conda" create -y -n "$(CONDA_ENV)" python=$(PYTHON_VERSION))
