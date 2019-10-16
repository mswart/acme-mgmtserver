#!/bin/bash
set -e

export FAKE_DNS=$(ip addr show docker0 | awk 'match($0, /([0-9.]+)\/[0-9]+/, a) { print a[1] }')
sed -i -e s/127.0.0.1:5002/${FAKE_DNS}:5002/ configs/integration-pebble.ini

mkdir -p ~/build/letsencrypt/pebble
cd ~/build/letsencrypt/pebble

wget https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/pebble.minica.pem
wget https://raw.githubusercontent.com/letsencrypt/pebble/master/docker-compose.yml

sed -i -e 's/ -strict//' docker-compose.yml

docker-compose up -d

pip install dnslib

echo 'waiting for pebble to be functional ...'

while true; do
  curl --cacert pebble.minica.pem https://127.0.0.1:14000/dir && break
  sleep 1
  if [[ "$SECONDS" -gt 300 ]]; then
    echo 'setup took more than 5 minutes, give up  :-('
    docker-compose logs
    exit 3
  fi
done

docker-compose logs
