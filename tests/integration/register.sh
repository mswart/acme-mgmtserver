#!/bin/bash
set -ex
mkdir -p tests/integration/account tests/integration/log
rm -f tests/integration/account/*
bin/acme-register --gen-key --register --email test@example.test configs/integration.ini | tee tests/integration/log/register.log
if grep 'You need to accept the terms of service' tests/integration/log/register.log > /dev/null; then
    bin/acme-register --accept-terms-of-service=`grep -E --only-matching http://.* tests/integration/log/register.log` configs/integration.ini
fi
echo 'final check'
bin/acme-register configs/integration.ini
