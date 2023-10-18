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
APP_VERSION ?= 3.36.0
APP_INI     ?= $(APP_ROOT)/config/$(APP_NAME).ini

# guess OS (Linux, Darwin,...)
OS_NAME := $(shell uname -s 2>/dev/null || echo "unknown")
CPU_ARCH := $(shell uname -m 2>/dev/null || uname -p 2>/dev/null || echo "unknown")

# conda
CONDA_ENV_NAME ?= $(APP_NAME)
CONDA_HOME     ?= $(HOME)/.conda
CONDA_ENVS_DIR ?= $(CONDA_HOME)/envs
CONDA_ENV_PATH := $(CONDA_ENVS_DIR)/$(CONDA_ENV_NAME)
# allow pre-installed conda in Windows bash-like shell
ifeq ($(findstring MINGW,$(OS_NAME)),MINGW)
  CONDA_BIN := $(shell which conda 2>/dev/null)
  ifneq ("$(CONDA_BIN)","")
    CONDA_BIN_DIR := $(shell dirname "$(CONDA_BIN)")
    CONDA_HOME := $(shell dirname "$(CONDA_BIN_DIR)")
  else
    CONDA_BIN_DIR ?= $(CONDA_HOME)/Scripts
  endif
else
  CONDA_BIN_DIR ?= $(CONDA_HOME)/bin
endif
CONDA_BIN := $(CONDA_BIN_DIR)/conda
CONDA_ENV_REAL_TARGET_PATH := $(realpath $(CONDA_ENV_PATH))
CONDA_ENV_REAL_ACTIVE_PATH := $(realpath ${CONDA_PREFIX})
CONDA_SETUP := 1

# environment already active - use it directly
ifneq ("$(CONDA_ENV_REAL_ACTIVE_PATH)", "")
  CONDA_ENV_MODE := [using active environment]
  CONDA_ENV_NAME := $(notdir $(CONDA_ENV_REAL_ACTIVE_PATH))
  CONDA_CMD :=
  CONDA_SETUP := 0
endif
# environment not active but it exists - activate and use it
ifneq ($(CONDA_ENV_REAL_TARGET_PATH), "")
  CONDA_ENV_NAME := $(notdir $(CONDA_ENV_REAL_TARGET_PATH))
  CONDA_SETUP := 0
endif
# environment not active and not found - create, activate and use it
ifeq ("$(CONDA_ENV_NAME)", "")
  CONDA_ENV_NAME := $(APP_NAME)
endif
# update paths for environment activation
ifeq ("$(CONDA_ENV_REAL_ACTIVE_PATH)", "")
  CONDA_ENV_MODE := [will activate environment]
  CONDA_CMD := source "$(CONDA_BIN_DIR)/activate" "$(CONDA_ENV_NAME)";
  CONDA_SETUP := 0
endif
# override conda command as desired
CONDA_COMMAND ?= undefined
ifneq ("$(CONDA_COMMAND)","undefined")
  CONDA_SETUP := 0
  CONDA_ENV_MODE := [using overridden command]
  CONDA_CMD := $(CONDA_COMMAND)
endif

DOWNLOAD_CACHE ?= $(APP_ROOT)/downloads
REPORTS_DIR ?= $(APP_ROOT)/reports
PYTHON_VERSION ?= `python -c 'import platform; print(platform.python_version())'`
PIP_XARGS ?=
PIP_USE_FEATURE := `python -c '\
	import pip; \
	try: \
		from packaging.version import Version as LooseVersion; \
	except Exception: \
		from distutils.version import LooseVersion; \
	print(LooseVersion(pip.__version__) < LooseVersion("21.0"))'`
PIP_DISABLE_FEATURE := `python -c '\
	import pip; \
	try: \
		from packaging.version import Version as LooseVersion; \
	except Exception: \
		from distutils.version import LooseVersion; \
	print(LooseVersion(pip.__version__) >= LooseVersion("22.0"))'`
ifeq ($(findstring "--use-feature=2020-resolver",$(PIP_XARGS)),)
  # feature not specified, but needed
  ifeq ("$(PIP_USE_FEATURE)", "True")
    PIP_XARGS := --use-feature=2020-resolver $(PIP_XARGS)
  else
    # use faster legacy resolver
    ifeq ($(PIP_DISABLE_FEATURE), "False")
      ifeq ($(findstring "--use-deprecated=legacy-resolver",$(PIP_XARGS)),)
        PIP_XARGS := --use-deprecated=legacy-resolver $(PIP_XARGS)
      endif
    endif
    ifeq ($(findstring "--use-feature=fast-deps",$(PIP_XARGS)),)
      PIP_XARGS := --use-feature=fast-deps $(PIP_XARGS)
    endif
  endif
else
  # feature was specified, but should not (not required anymore, default behavior)
  ifeq ("$(PIP_USE_FEATURE)", "True")
    PIP_XARGS := $(subst "--use-feature=2020-resolver",,$(PIP_XARGS))
  else
    # use faster legacy resolver
    ifeq ($(PIP_DISABLE_FEATURE), "False")
      ifeq ($(findstring "--use-deprecated=legacy-resolver",$(PIP_XARGS)),)
        PIP_XARGS := --use-deprecated=legacy-resolver $(PIP_XARGS)
      endif
    endif
    ifeq ($(findstring "--use-feature=fast-deps",$(PIP_XARGS)),)
      PIP_XARGS := --use-feature=fast-deps $(PIP_XARGS)
    endif
  endif
endif

# choose conda installer depending on your OS
CONDA_URL = https://repo.continuum.io/miniconda
ifeq ("$(OS_NAME)", "Linux")
  FN := Miniconda3-latest-Linux-x86_64.sh
else ifeq ("$(OS_NAME)", "Darwin")
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
_SPACING := 24
.PHONY: help
# note: use "\#\#" to escape results that would self-match in this target's search definition
help:	## print this help message (default)
	@echo "$(_SECTION)=== $(APP_NAME) help ===$(_NORMAL)"
	@echo "Please use 'make <target>' where <target> is one of:"
#	@grep -E '^[a-zA-Z_-]+:.*?\#\# .*$$' $(MAKEFILE_LIST) \
#		| awk 'BEGIN {FS = ":.*?\#\# "}; {printf "    $(_TARGET)%-24s$(_NORMAL) %s\n", $$1, $$2}'
	@grep -E '\#\#.*$$' "$(APP_ROOT)/$(MAKEFILE_NAME)" \
		| awk ' BEGIN {FS = "(:|\-\-\-)+.*?\#\# "}; \
			/\--/ 		{printf "$(_SECTION)%s$(_NORMAL)\n", $$1;} \
			/:/   		{printf "   $(_TARGET)%-$(_SPACING)s$(_NORMAL) %s\n", $$1, $$2;} \
			/\-only:/   {gsub(/-only/, "", $$1); \
						 printf "   $(_TARGET)%-$(_SPACING)s$(_NORMAL) %s (preinstall dependencies)\n", $$1, $$2;} \
		'

.PHONY: version
version:	## display current version
	@-echo "$(APP_NAME) version: $(APP_VERSION)"

.PHONY: info
info:		## display make information
	@echo "Information about your make execution:"
	@echo "  OS Name                $(OS_NAME)"
	@echo "  CPU Architecture       $(CPU_ARCH)"
	@echo "  Conda Home             $(CONDA_HOME)"
	@echo "  Conda Prefix           $(CONDA_ENV_PATH)"
	@echo "  Conda Env Name         $(CONDA_ENV_NAME)"
	@echo "  Conda Env Path         $(CONDA_ENV_REAL_ACTIVE_PATH)"
	@echo "  Conda Binary           $(CONDA_BIN)"
	@echo "  Conda Activation       $(CONDA_ENV_MODE)"
	@echo "  Conda Command          $(CONDA_CMD)"
	@echo "  Application Root       $(APP_ROOT)"
	@echo "  Application Name       $(APP_NAME)"
	@echo "  Application Version    $(APP_VERSION)"
	@echo "  Download Cache         $(DOWNLOAD_CACHE)"
	@echo "  Test Reports           $(REPORTS_DIR)"
	@echo "  Docker Tag (magpie)    $(MAGPIE_DOCKER_TAG)"
	@echo "  Docker Tag (twitcher)  $(TWITCHER_DOCKER_TAG)"

## --- Cleanup targets --- ##

.PHONY: clean
clean: clean-all	## alias for 'clean-all' target

.PHONY: clean-all
clean-all: clean-build clean-pyc clean-test clean-report clean-docs		## remove all artifacts

.PHONY: clean-build
clean-build:	## remove build artifacts
	@echo "Cleaning build artifacts..."
	@-rm -fr build/
	@-rm -fr dist/
	@-rm -fr downloads/
	@-rm -fr .eggs/
	@find . -type d -name '*.egg-info' -exec rm -fr {} +
	@find . -type f -name '*.egg' -exec rm -f {} +

# rm without quotes important below to allow regex
.PHONY: clean-docs
clean-docs:		## remove doc artifacts
	@echo "Cleaning doc artifacts..."
	@-find "$(APP_ROOT)/docs/" -type f -name "$(APP_NAME)*.rst" -delete
	@-rm -f "$(APP_ROOT)/docs/modules.rst"
	@-rm -f "$(APP_ROOT)/docs/api.json"
	@-rm -rf "$(APP_ROOT)/docs/autoapi"
	@-rm -rf "$(APP_ROOT)/docs/_build"

.PHONY: clean-pyc
clean-pyc:		## remove Python file artifacts
	@echo "Cleaning Python artifacts..."
	@find . -type f -name '*.pyc' -exec rm -f {} +
	@find . -type f -name '*.pyo' -exec rm -f {} +
	@find . -type f -name '*~' -exec rm -f {} +
	@find . -type f -name '__pycache__' -exec rm -fr {} +

.PHONY: clean-report
clean-report: 	## remove check linting reports
	@echo "Cleaning check linting reports..."
	@-rm -fr "$(REPORTS_DIR)"

.PHONY: clean-test
clean-test: clean-report	## remove test and coverage artifacts
	@echo "Cleaning tests artifacts..."
	@-rm -fr .tox/
	@-rm -fr .pytest_cache/
	@-rm -f .coverage*
	@-rm -f coverage.*
	@-rm -fr "$(APP_ROOT)/coverage/"
	@-rm -fr "$(APP_ROOT)/node_modules"
	@-rm -f "$(APP_ROOT)/package-lock.json"

.PHONY: clean-docker
clean-docker: docker-clean	## remove docker images (alias for 'docker-clean' target)

## --- Database targets --- ##

.PHONY: _alembic
_alembic: conda-env
	@bash -c '$(CONDA_CMD) test -f "$(CONDA_ENV_PATH)/bin/alembic" || pip install $(PIP_XARGS) alembic'

.PHONY: migrate
migrate: database-migration		## alias to 'database-migration'

DB_REVISION ?= head
DB_COMMAND := MAGPIE_INI_FILE_PATH="$(APP_INI)" alembic -c "$(APP_INI)"

.PHONY: database-migration
database-migration: conda-env _alembic 	## run database migration (make [REVISION=head,<empty=1>,ID] database-migration)
	@echo "Running database upgrade migration (using revision: [$(DB_REVISION)])..."
	@bash -c '$(CONDA_CMD) $(DB_COMMAND) upgrade $(DB_REVISION)'

.PHONY: database-upgrade
database-upgrade: database-migration	## run database upgrade to more recent version (alias to 'database-migration')

.PHONY: database-downgrade
database-downgrade: conda-env _alembic  ## run database downgrade to older version (inverse of 'database-upgrade')
	echo "$(DB_REVISION)"
	echo "${DB_REVISION}"
	@[ "$(DB_REVISION)" != "head" ] || ( echo ">> Invalid 'DB_REVISION' cannot be 'head' to downgrade."; exit 1 )
	@echo "Running database downgrade migration (using revision: [$(DB_REVISION)])..."
	@bash -c '$(CONDA_CMD) $(DB_COMMAND) downgrade $(DB_REVISION)'

.PHONY: database-history
database-history: conda-env _alembic    ## obtain database revision history
	@bash -c '$(CONDA_CMD) $(DB_COMMAND) history'

.PHONY: database-revision
database-revision: conda-env _alembic   ## create a new database revision
	@[ "${DOC}" ] || ( echo ">> 'DOC' is not set. Provide a description."; exit 1 )
	@bash -c '$(CONDA_CMD) $(DB_COMMAND) revision -m "$(DOC)"'

.PHONY: database-version
database-version: conda-env _alembic 	## retrieve current database revision ID
	@echo "Fetching database revision..."
	@bash -c '$(CONDA_CMD) $(DB_COMMAND) current'

## --- Documentation targets --- ##

DOC_LOCATION := $(APP_ROOT)/docs/_build/html/index.html
$(DOC_LOCATION):
	@echo "Building docs..."
	@bash -c '$(CONDA_CMD) \
		sphinx-apidoc -o "$(APP_ROOT)/docs/" "$(APP_ROOT)/$(APP_NAME)"; \
		"$(MAKE)" -C "$(APP_ROOT)/docs" html;'
	@-echo "Documentation available: file://$(DOC_LOCATION)"

.PHONY: _force_docs
_force_docs:
	@-rm -f "$(DOC_LOCATION)"

.PHONY: docs-only
docs-only: _force_docs $(DOC_LOCATION) 	## generate documentation without requirements installation or cleanup

# NOTE: we need almost all base dependencies because magpie package needs to be parsed to generate OpenAPI
.PHONY: docs
docs: install-docs install-pkg clean-docs docs-only	## generate Sphinx HTML documentation, including API docs

.PHONY: docs-show
docs-show: $(DOC_LOCATION)	## display HTML webpage of generated documentation (build docs if missing)
	@-test -f "$(DOC_LOCATION)" || $(MAKE) -C "$(APP_ROOT)" docs
	$(BROWSER) "$(DOC_LOCATION)"

## --- Versioning targets --- ##

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
bump:	## bump version using VERSION specified as user input (make VERSION=<X.Y.Z> bump)
	@-echo "Updating package version ..."
	@[ "${VERSION}" ] || ( echo ">> 'VERSION' is not set"; exit 1 )
	@-bash -c '$(CONDA_CMD) test -f "$(CONDA_ENV_PATH)/bin/bump2version" || pip install $(PIP_XARGS) bump2version'
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

.PHONY: install-all
install-all: install-sys install-pkg install-dev install-docs	## install every dependency and package definition

.PHONY: install-xargs
install-xargs:
	@echo "Using PIP_XARGS: $(PIP_XARGS)"

# note: don't use PIP_XARGS for install system package as it could be upgrade of pip that doesn't yet have those options
.PHONY: install-sys
install-sys: clean conda-env install-xargs	## install system dependencies and required installers/runners
	@echo "Installing system dependencies..."
	@bash -c '$(CONDA_CMD) pip install --upgrade -r "$(APP_ROOT)/requirements-sys.txt"'

.PHONY: install-pkg
install-pkg: install-sys install-xargs	## install the package to the active Python's site-packages
	@echo "Installing Magpie..."
	@bash -c '$(CONDA_CMD) python setup.py install_egg_info'
	@bash -c '$(CONDA_CMD) pip install $(PIP_XARGS) --upgrade -e "$(APP_ROOT)" '
	# TODO: remove when merged
	# --- ensure fix is applied
	@bash -c '$(CONDA_CMD) \
		pip install $(PIP_XARGS) --force-reinstall \
			"https://github.com/fmigneault/authomatic/archive/httplib-port.zip#egg=Authomatic"'
	# ---

.PHONY: install-req
install-req: conda-env install-xargs	 ## install package base requirements without installing main package
	@bash -c '$(CONDA_CMD) pip install $(PIP_XARGS) -r "$(APP_ROOT)/requirements.txt"'
	@echo "Successfully installed base requirements."

.PHONY: install-docs
install-docs: conda-env install-xargs  ## install package requirements for documentation generation
	@bash -c '$(CONDA_CMD) pip install $(PIP_XARGS) -r "$(APP_ROOT)/requirements-doc.txt"'
	@echo "Successfully installed docs requirements."

.PHONY: install-dev
install-dev: conda-env install-xargs	## install package requirements for development and testing
	@bash -c '$(CONDA_CMD) pip install $(PIP_XARGS) -r "$(APP_ROOT)/requirements-dev.txt"'
	@echo "Successfully installed dev requirements."

# install locally to ensure they can be found by config extending them
.PHONY: install-npm
install-npm:    		## install npm package manager if it cannot be found
	@[ -f "$(shell which npm)" ] || ( \
		echo "Binary package manager npm not found. Attempting to install it."; \
		apt-get install npm \
	)
	@[ `npm ls -only dev -depth 0 2>/dev/null | grep -V "UNMET" | grep stylelint-config-standard | wc -l` = 1 ] || ( \
		echo "Install required libraries for style checks." && \
		npm install stylelint@13.13.1 stylelint-config-standard@22.0.0 --save-dev \
	)

## --- Launchers targets --- ##

.PHONY: cron
cron:
	@echo "Starting Cron service..."
	cron

.PHONY: start
start: install start-app  ## start application instance with gunicorn after installation of dependencies

.PHONY: start-app
start-app: stop		## start application instance with gunicorn
	@echo "Starting $(APP_NAME)..."
	@bash -c '$(CONDA_CMD) pserve "$(APP_INI)" "bind=127.0.0.1:2001" --reload &'
	@sleep 5
	@curl -H "Accept: application/json" "http://localhost:2001/version" | grep '"code": 200'

.PHONY: stop
stop: 		## kill application instance(s) started with gunicorn
	@(lsof -t -i :2001 | xargs kill) 2>/dev/null || echo "No $(APP_NAME) process to stop"

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
.PHONY: docker-test-only
docker-test-only:	## execute smoke test of the built image for Magpie application (validate that it boots)
	@echo "Smoke test of built application docker image"
	docker-compose $(DOCKER_TEST_COMPOSES) up -d
	sleep 5
	curl localhost:2001 | grep "Magpie Administration"
	docker-compose $(DOCKER_TEST_COMPOSES) stop

.PHONY: docker-test
docker-test: docker-build-magpie docker-test-only	## execute smoke test of the built image for Magpie application (validate that it boots)

.PHONY: docker-test-stop
docker-test-stop:  ## explicitly stop any running instance that could remain from 'docker-test' target
	docker-compose $(DOCKER_TEST_COMPOSES) stop

.PHONY: docker-clean
docker-clean: 	## remove any leftover images from docker target operations
	docker rmi $(docker images -f "reference=$(MAGPIE_DOCKER_REPO)" -q)
	docker-compose $(DOCKER_TEST_COMPOSES) down

## --- Static code check targets ---

.PHONY: mkdir-reports
mkdir-reports:
	@mkdir -p "$(REPORTS_DIR)"

# autogen check variants with pre-install of dependencies using the '-only' target references
CHECKS := pep8 lint security security-code security-deps doc8 links imports css
CHECKS := $(addprefix check-, $(CHECKS))

$(CHECKS): check-%: install-dev check-%-only

.PHONY: check
check: install-dev $(CHECKS)  ## run code checks (alias to 'check-all' target)

# undocumented to avoid duplicating aliases in help listing
.PHONY: check-only
check-only: check-all-only

.PHONY: check-all-only
check-all-only: $(addsuffix -only, $(CHECKS))  ## run all code checks
	@echo "All checks passed!"

.PHONY: check-pep8-only
check-pep8-only: mkdir-reports		## run PEP8 code style checks
	@echo "Running PEP8 code style checks..."
	@-rm -fr "$(REPORTS_DIR)/check-pep8.txt"
	@bash -c '$(CONDA_CMD) \
		flake8 --config="$(APP_ROOT)/setup.cfg" --output-file="$(REPORTS_DIR)/check-pep8.txt" --tee'

.PHONY: check-lint-only
check-lint-only: mkdir-reports		## run linting code style checks
	@echo "Running linting code style checks..."
	@-rm -fr "$(REPORTS_DIR)/check-lint.txt"
	@bash -c '$(CONDA_CMD) \
		pylint \
			--load-plugins pylint_quotes \
			--rcfile="$(APP_ROOT)/.pylintrc" \
			--reports y \
			"$(APP_ROOT)/$(APP_NAME)" "$(APP_ROOT)/$(APP_NAME)/alembic" "$(APP_ROOT)/docs" "$(APP_ROOT)/tests" \
		1> >(tee "$(REPORTS_DIR)/check-lint.txt")'

.PHONY: check-security-only
check-security-only: check-security-code-only check-security-deps-only  ## run security checks

# ignored codes:
#	42194: https://github.com/kvesteri/sqlalchemy-utils/issues/166  # not fixed since 2015
#	51668: https://github.com/sqlalchemy/sqlalchemy/pull/8563  # still in beta + major version change sqlalchemy 2.0.0b1
.PHONY: check-security-deps-only
check-security-deps-only: mkdir-reports  ## run security checks on package dependencies
	@echo "Running security checks of dependencies..."
	@-rm -fr "$(REPORTS_DIR)/check-security-deps.txt"
	@bash -c '$(CONDA_CMD) \
		safety check \
			-r "$(APP_ROOT)/requirements.txt" \
			-r "$(APP_ROOT)/requirements-dev.txt" \
			-r "$(APP_ROOT)/requirements-doc.txt" \
			-r "$(APP_ROOT)/requirements-sys.txt" \
			-i 42194 \
			-i 51668 \
		1> >(tee "$(REPORTS_DIR)/check-security-deps.txt")'

.PHONY: check-security-code-only
check-security-code-only: mkdir-reports  ## run security checks on source code
	@echo "Running security code checks..."
	@-rm -fr "$(REPORTS_DIR)/check-security-code.txt"
	@bash -c '$(CONDA_CMD) \
		bandit -v --ini "$(APP_ROOT)/setup.cfg" -r \
		1> >(tee "$(REPORTS_DIR)/check-security-code.txt")'

.PHONY: check-docs-only
check-docs-only: check-doc8-only check-docf-only check-links-only	## run every code documentation checks

# FIXME: temporary workaround (https://github.com/PyCQA/doc8/issues/145 and https://github.com/PyCQA/doc8/issues/147)
# 		configuration somehow not picked up directly from setup.cfg in python 3.11
#		setting 'ignore-path-errors' not working without the full path (relative 'docs/changes.rst' fails)
CHECK_DOC8_XARGS := --ignore-path-errors "$(APP_ROOT)/docs/changes.rst;D000"

.PHONY: check-doc8-only
check-doc8-only: mkdir-reports		## run PEP8 documentation style checks
	@echo "Running PEP8 doc style checks..."
	@-rm -fr "$(REPORTS_DIR)/check-doc8.txt"
	@bash -c '$(CONDA_CMD) \
		doc8 --config "$(APP_ROOT)/setup.cfg" "$(APP_ROOT)/docs" \
			$(CHECK_DOC8_XARGS) \
		1> >(tee "$(REPORTS_DIR)/check-doc8.txt")'

# FIXME: move parameters to setup.cfg when implemented (https://github.com/myint/docformatter/issues/10)
# NOTE: docformatter only reports files with errors on stderr, redirect trace stderr & stdout to file with tee
# NOTE:
#	Don't employ '--wrap-descriptions 120' since they *enforce* that length and rearranges format if any word can fit
#	within remaining space, which often cause big diffs of ugly formatting for no important reason. Instead only check
#	general formatting operations, and let other linter capture docstrings going over 120 (what we really care about).
.PHONY: check-docf-only
check-docf-only: mkdir-reports	## run PEP8 code documentation format checks
	@echo "Checking PEP8 doc formatting problems..."
	@-rm -fr "$(REPORTS_DIR)/check-docf.txt"
	@bash -c '$(CONDA_CMD) \
		docformatter \
			--pre-summary-newline \
			--wrap-descriptions 0 \
			--wrap-summaries 120 \
			--make-summary-multi-line \
			--check \
			--recursive \
			"$(APP_ROOT)" \
		1>&2 2> >(tee "$(REPORTS_DIR)/check-docf.txt")'

.PHONY: check-links-only
check-links-only: mkdir-reports		## run check of external links in documentation for integrity
	@echo "Running link checks on docs..."
	@bash -c '$(CONDA_CMD) $(MAKE) -C "$(APP_ROOT)/docs" linkcheck'

.PHONY: check-imports-only
check-imports-only: mkdir-reports	## run imports code checks
	@echo "Running import checks..."
	@-rm -fr "$(REPORTS_DIR)/check-imports.txt"
	@bash -c '$(CONDA_CMD) \
	 	isort --check-only --diff --recursive $(APP_ROOT) \
		1> >(tee "$(REPORTS_DIR)/check-imports.txt")'

.PHONY: check-css-only
check-css-only: mkdir-reports install-npm
	@echo "Running CSS style checks..."
	@npx stylelint \
		--config "$(APP_ROOT)/.stylelintrc.json" \
		--output-file "$(REPORTS_DIR)/fixed-css.txt" \
		"$(APP_ROOT)/**/*.css"

# autogen fix variants with pre-install of dependencies using the '-only' target references
FIXES := imports lint docf css
FIXES := $(addprefix fix-, $(FIXES))

$(FIXES): fix-%: install-dev fix-%-only

.PHONY: fix
fix: fix-all    ## run all fixes (alias for 'fix-all' target)

# undocumented to avoid duplicating aliases in help listing
.PHONY: fix-only
fix-only: $(addsuffix -only, $(FIXES))

.PHONY: fix-all-only
fix-all-only: $(FIXES)  ## fix all code check problems automatically
	@echo "All fixes applied!"

.PHONY: fix-imports-only
fix-imports-only: 	## fix import code checks corrections automatically
	@echo "Fixing flagged import checks..."
	@-rm -fr "$(REPORTS_DIR)/fixed-imports.txt"
	@bash -c '$(CONDA_CMD) \
		isort --recursive $(APP_ROOT) \
		1> >(tee "$(REPORTS_DIR)/fixed-imports.txt")'

.PHONY: fix-lint-only
fix-lint-only: mkdir-reports	## fix some PEP8 code style problems automatically
	@echo "Fixing PEP8 code style problems..."
	@-rm -fr "$(REPORTS_DIR)/fixed-lint.txt"
	@bash -c '$(CONDA_CMD) \
		autopep8 -v -j 0 -i -r $(APP_ROOT) \
		1> >(tee "$(REPORTS_DIR)/fixed-lint.txt")'

# FIXME: move parameters to setup.cfg when implemented (https://github.com/myint/docformatter/issues/10)
.PHONY: fix-docf-only
fix-docf-only: mkdir-reports	## fix some PEP8 code documentation style problems automatically
	@echo "Fixing PEP8 code documentation problems..."
	@-rm -fr "$(REPORTS_DIR)/fixed-docf.txt"
	@bash -c '$(CONDA_CMD) \
		docformatter \
			--pre-summary-newline \
			--wrap-descriptions 0 \
			--wrap-summaries 120 \
			--make-summary-multi-line \
			--in-place \
			--recursive \
			$(APP_ROOT) \
		1> >(tee "$(REPORTS_DIR)/fixed-docf.txt")'

.PHONY: fix-css-only
fix-css-only: mkdir-reports install-npm		## fix CSS styles problems automatically
	@echo "Fixing CSS style problems..."
	@npx stylelint \
		--fix \
		--config "$(APP_ROOT)/.stylelintrc.json" \
		--output-file "$(REPORTS_DIR)/fixed-css.txt" \
		"$(APP_ROOT)/**/*.css"

## --- Test targets --- ##


# -v:  list of test names with PASS/FAIL/SKIP/ERROR/etc. next to it
# -vv: extended collection of stdout/stderr on top of test results
TEST_VERBOSITY ?= -vv
# any valid log level: DEBUG|INFO|WARNING|ERROR|FATAL|CRITICAL
# log calls will be collected if greater or equal to this value during tests
TEST_LOG_LEVEL ?=
ifneq ($(TEST_LOG_LEVEL),)
  override TEST_LOG_LEVEL := --log-cli-level $(shell echo $(TEST_LOG_LEVEL) | tr '[:lower:]' '[:upper:]')
endif

# autogen tests variants with pre-install of dependencies using the '-only' target references
TESTS := cli local remote custom
TESTS := $(addprefix test-, $(TESTS))

$(TESTS): test-%: install install-dev test-%-only

.PHONY: test
test: clean-test test-all   ## run tests (alias for 'test-all' target)

.PHONY: test-all
test-all: install install-dev test-only  ## run all tests (including long running tests)

.PHONY: test-only
test-only: mkdir-reports		 ## run all tests combinations without pre-installation of dependencies
	@echo "Running tests..."
	@bash -c '$(CONDA_CMD) pytest tests $(TEST_VERBOSITY) $(TEST_LOG_LEVEL) \
		--junitxml "$(APP_ROOT)/tests/results.xml"'

.PHONY: test-cli-only
test-cli-only: 		## run only CLI tests with the environment Python
	@echo "Running local tests..."
	@bash -c '$(CONDA_CMD) pytest tests $(TEST_VERBOSITY) $(TEST_LOG_LEVEL) \
		-m "cli" --junitxml "$(APP_ROOT)/tests/results.xml"'

# note: use 'not remote' instead of 'local' to capture other low-level tests like 'utils' unittests
.PHONY: test-local-only
test-local-only: 		## run only local tests with the environment Python
	@echo "Running local tests..."
	bash -c '$(CONDA_CMD) pytest tests $(TEST_VERBOSITY) $(TEST_LOG_LEVEL) \
		-m "not remote" --junitxml "$(APP_ROOT)/tests/results.xml"'

.PHONY: test-remote-only
test-remote-only:		## run only remote tests with the environment Python
	@echo "Running remote tests..."
	@bash -c '$(CONDA_CMD) pytest tests $(TEST_VERBOSITY) $(TEST_LOG_LEVEL) \
		-m "remote" --junitxml "$(APP_ROOT)/tests/results.xml"'

# https://docs.pytest.org/en/7.1.x/example/markers.html#mark-examples
# https://docs.pytest.org/en/7.1.x/example/markers.html#using-k-expr-to-select-tests-based-on-their-name
.PHONY: test-custom-only
test-custom-only:		## run custom tests [example: SPEC="<marker1> or (<marker2> and not test_func or TestClass)"]
	@echo "Running custom tests..."
	@[ "${SPEC}" ] || ( echo ">> 'SPEC' is not set"; exit 1 )
	@bash -c '$(CONDA_CMD) pytest tests $(TEST_VERBOSITY) $(TEST_LOG_LEVEL) \
		-k "${SPEC}" --junitxml "$(APP_ROOT)/tests/results.xml"'

.PHONY: test-docker
test-docker: docker-test	## run test with docker (alias for 'docker-test' target) - WARNING: build image if missing

# for consistency only with other test
test-docker-only: docker-test-only	## run test with docker (alias for 'docker-test' target) - WARNING: build image if missing

# coverage file location cannot be changed
COVERAGE_FILE     := $(APP_ROOT)/.coverage
COVERAGE_HTML_DIR := $(REPORTS_DIR)/coverage
COVERAGE_HTML_IDX := $(COVERAGE_HTML_DIR)/index.html
$(COVERAGE_FILE): install-dev
	@echo "Running coverage analysis..."
	@bash -c '$(CONDA_CMD) coverage run --source "$(APP_ROOT)/$(APP_NAME)" \
		`which pytest` tests $(TEST_VERBOSITY) $(TEST_LOG_LEVEL) -m "not remote" || true'
	@bash -c '$(CONDA_CMD) coverage xml -i -o "$(REPORTS_DIR)/coverage.xml"'
	@bash -c '$(CONDA_CMD) coverage report -m'
	@bash -c '$(CONDA_CMD) coverage html -d "$(COVERAGE_HTML_DIR)"'
	@-echo "Coverage report available: file://$(COVERAGE_HTML_IDX)"

.PHONY: coverage-only
coverage-only: $(COVERAGE_FILE)

.PHONY: coverage
coverage: install-dev install coverage-only		## run tests with code coverage and generate an analysis report

.PHONY: coverage-show
coverage-show: $(COVERAGE_HTML_IDX)		## display HTML webpage of generated coverage report (run coverage if missing)
	@-test -f "$(COVERAGE_HTML_IDX)" || $(MAKE) -C "$(APP_ROOT)" coverage
	$(BROWSER) "$(COVERAGE_HTML_IDX)"

## --- Conda setup targets --- ##

.PHONY: conda-base
conda-base:	 ## obtain a base distribution of conda if missing and required
	@[ $(CONDA_SETUP) -eq 0 ] && echo "Conda setup disabled." || ( ( \
		test -f "$(CONDA_BIN)" || test -d "$(DOWNLOAD_CACHE)" || ( \
			echo "Creating download directory: $(DOWNLOAD_CACHE)" && \
			mkdir -p "$(DOWNLOAD_CACHE)") ) ; ( \
		test -f "$(CONDA_BIN)" || \
		test -f "$(DOWNLOAD_CACHE)/$(FN)" || ( \
			echo "Fetching conda distribution from: $(CONDA_URL)/$(FN)" && \
		 	curl "$(CONDA_URL)/$(FN)" --insecure --location --output "$(DOWNLOAD_CACHE)/$(FN)") ) ; ( \
		test -f "$(CONDA_BIN)" || ( \
		  	bash "$(DOWNLOAD_CACHE)/$(FN)" -b -u -p "$(CONDA_HOME)" && \
		 	echo "Make sure to add '$(CONDA_HOME)/bin' to your PATH variable in '~/.bashrc'.") ) \
	)

.PHONY: conda-cfg
conda_config: conda-base	## update conda package configuration
	@echo "Updating conda configuration..."
	@"$(CONDA_BIN)" config --set ssl_verify true
	@"$(CONDA_BIN)" config --set use_pip true
	@"$(CONDA_BIN)" config --set channel_priority true
	@"$(CONDA_BIN)" config --set auto_update_conda false
	@"$(CONDA_BIN)" config --add channels defaults

# the conda-env target's dependency on conda-cfg above was removed, will add back later if needed

.PHONY: conda-env
conda-env: conda-base	## create conda environment if missing and required
	@[ $(CONDA_SETUP) -eq 0 ] || ( \
		test -d "$(CONDA_ENV_PATH)" || ( \
			echo "Creating conda environment at '$(CONDA_ENV_PATH)'..." && \
		 	"$(CONDA_BIN)" create -y -n "$(CONDA_ENV_NAME)" python=$(PYTHON_VERSION)) \
		)
