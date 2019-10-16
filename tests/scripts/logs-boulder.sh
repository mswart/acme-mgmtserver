#!/bin/bash
set -e

export GOPATH=~/build/go
cd $GOPATH/src/github.com/letsencrypt/boulder

docker-compose logs
