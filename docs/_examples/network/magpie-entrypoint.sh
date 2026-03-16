#! /usr/bin/env bash

sed -i "s:^prefix = /magpie:prefix = ${MAGPIE_PREFIX}:" config/magpie.ini

exec pserve config/magpie.ini
