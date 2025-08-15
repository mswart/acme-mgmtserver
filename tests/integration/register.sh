#!/bin/bash
if [[ "$1" = 'generic' ]]; then
    # we do not have any ACME server as backend
    exit 0
fi
if [[ "$1" = 'pebble' ]]; then
    export ACME_CAFILE=~/build/letsencrypt/pebble/pebble.minica.pem
fi
set -ex
mkdir -p tests/integration/account tests/integration/log
rm -f tests/integration/account/*
acme-register --gen-key --register --email integration-$1@ci$$.org --accept-terms-of-service='something' configs/integration-$1.ini
echo 'final check'
acme-register configs/integration-$1.ini
