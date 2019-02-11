FROM python:2.7-alpine
MAINTAINER Francis Charette-Migneault

ARG MAGPIE_DIR=/opt/local/src/magpie
ENV MAGPIE_ENV_DIR=$MAGPIE_DIR/env
WORKDIR $MAGPIE_DIR

# magpie cron service
ADD magpie-cron /etc/cron.d/magpie-cron
RUN chmod 0644 /etc/cron.d/magpie-cron
RUN touch ~/magpie_cron_status.log
# set /etc/environment so that cron runs using the environment variables set by docker
RUN env >> /etc/environment

COPY magpie/__init__.py magpie/__meta__.py ./magpie/
COPY requirements* Makefile setup.py README.rst HISTORY.rst ./

# The command `apk add --virtual .build-deps ... apk --purge del .build-deps`
# Installs the packages and removes them afterwards.
# Packages like gcc and python-dev are required for building, but not at runtime.

RUN apk update && apk add \
    bash \
    postgresql-libs \
    libxslt-dev && \
    apk add --virtual .build-deps \
    libffi-dev \
    gcc \
    python-dev \
    musl-dev \
    postgresql-dev && \
    pip install --no-cache-dir --upgrade pip gunicorn setuptools && \
    pip install --no-cache-dir -e . && \
    pip install https://github.com/fmigneault/authomatic/archive/httplib-port.zip#egg=Authomatic && \
    apk --purge del .build-deps

COPY . .

RUN pip install --no-dependencies -e .

CMD crond && gunicorn -b 0.0.0.0:2001 --paste ./magpie/magpie.ini --workers 10 --preload
