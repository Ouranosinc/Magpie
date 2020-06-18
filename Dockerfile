FROM python:3.7-alpine
LABEL Description="Runs Magpie AuthN/AuthZ service for REST-API and UI interfaces."
LABEL Maintainer="Francis Charette-Migneault <francis.charette-migneault@crim.ca>"
LABEL Vendor="CRIM"

# the cron service depends on the $MAGPIE_DIR environment variable
ENV MAGPIE_DIR=/opt/local/src/magpie
ENV MAGPIE_CONFIG_DIR=$MAGPIE_DIR/config
ENV MAGPIE_ENV_DIR=$MAGPIE_DIR/env
WORKDIR $MAGPIE_DIR

ENV CRON_DIR=/etc/crontabs

# magpie cron service
COPY magpie-cron $CRON_DIR/magpie-cron
RUN chmod 0644 $CRON_DIR/magpie-cron

# install dependencies
COPY magpie/__init__.py magpie/__meta__.py $MAGPIE_DIR/magpie/
COPY requirements* setup.py README.rst HISTORY.rst $MAGPIE_DIR/
RUN apk update \
    && apk add \
    bash \
    postgresql-libs \
    libxslt-dev \
    && apk add --virtual .build-deps \
    gcc \
    libffi-dev \
    python-dev \
    py-pip \
    musl-dev \
    postgresql-dev \
    && pip install --no-cache-dir --upgrade -r requirements-sys.txt \
    && pip install --no-cache-dir -e $MAGPIE_DIR \
    && apk --purge del .build-deps

# install app package source, avoid copying the rest
COPY ./bin $MAGPIE_DIR/bin/
COPY ./config/magpie.ini $MAGPIE_CONFIG_DIR/magpie.ini
COPY ./env/*.env.example $MAGPIE_ENV_DIR/
COPY ./magpie $MAGPIE_DIR/magpie/
# equivalent of `make install` without conda env and pre-installed packages
RUN pip install --no-dependencies -e $MAGPIE_DIR

# equivalent of `make cron start` without conda env
CMD crond -c $CRON_DIR && gunicorn -b 0.0.0.0:2001 --paste $MAGPIE_CONFIG_DIR/magpie.ini --workers 10 --preload
