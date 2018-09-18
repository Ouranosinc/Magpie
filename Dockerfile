FROM ubuntu:16.04
MAINTAINER Francis Charette-Migneault

RUN apt-get update && apt-get install -y \
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
	vim

ARG MAGPIE_DIR=/opt/local/src/magpie
ENV MAGPIE_ENV_DIR=$MAGPIE_DIR/env
WORKDIR $MAGPIE_DIR

COPY ./ $MAGPIE_DIR
RUN make install -f $MAGPIE_DIR/Makefile
RUN make docs -f $MAGPIE_DIR/Makefile

ADD magpie-cron /etc/cron.d/magpie-cron
RUN chmod 0644 /etc/cron.d/magpie-cron
RUN touch ~/magpie_cron_status.log

CMD make start
