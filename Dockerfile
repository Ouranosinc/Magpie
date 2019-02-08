FROM ubuntu:16.04
MAINTAINER Francis Charette-Migneault

RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	supervisor \
	cron \
	curl \
	libssl-dev \
	libffi-dev \
	python-dev \
	libxml2-dev \
	libxslt1-dev \
	zlib1g-dev \
	python-pip \
	git \
	vim \
	apt-get clean autoclean \
    apt-get autoremove --yes \
    rm -rf /var/lib/{apt,dpkg,cache,log}/

ARG MAGPIE_DIR=/opt/local/src/magpie
ENV MAGPIE_ENV_DIR=$MAGPIE_DIR/env
WORKDIR $MAGPIE_DIR

COPY ./ $MAGPIE_DIR
RUN make install -f $MAGPIE_DIR/Makefile
RUN make docs -f $MAGPIE_DIR/Makefile


CMD make start cron
