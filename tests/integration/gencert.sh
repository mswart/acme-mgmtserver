#!/bin/bash
set -ex
mkdir -p tests/integration/work
rm -f tests/integration/work/*
# generate domain private key (once!)
openssl genrsa 4096 > tests/integration/work/domain.key

openssl req -new -sha256 -key tests/integration/work/domain.key -subj "/CN=integration$$.org" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:integration$$.org,DNS:www.integration$$.org")) > tests/integration/work/domain-201512.csr

wget --post-file=tests/integration/work/domain-201512.csr --header="`openssl dgst -sha256 -hmac 'n048aX0G2Gc8zAvUfcbz8fFIpRwi1D' tests/integration/work/domain-201512.csr | sed -e 's/HMAC-\(.*\)(.*)= *\(.*\)/Authentication: hmac name=\L\1\E, hash=\2/'`" http://127.0.0.1:1313/sign -O tests/integration/work/domain-201512.pem
wget --post-file=tests/integration/work/domain-201512.csr --header="`openssl dgst -sha256 -hmac 'n048aX0G2Gc8zAvUfcbz8fFIpRwi1D' tests/integration/work/domain-201512.csr | sed -e 's/HMAC-\(.*\)(.*)= *\(.*\)/Authentication: hmac name=\L\1\E, hash=\2/'`" http://127.0.0.1:1313/sign -O tests/integration/work/domain-201512-2.pem
