FROM ubuntu:16.04
MAINTAINER Francis Charette-Migneault

RUN apt-get update && apt-get install -y \
	build-essential \
	supervisor \
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
WORKDIR $MAGPIE_DIR

COPY ./ $MAGPIE_DIR
RUN make install -f $MAGPIE_DIR/Makefile
RUN make docs -f $MAGPIE_DIR/Makefile

CMD ["make", "start", "-f", "$MAGPIE_DIR/Makefile"]
