#!/bin/bash
set -ex
eval "$(gimme 1.5)"
echo "$(gimme 1.5)"
export GOPATH=~/build/go
export PATH=$PATH:$GOPATH/bin
mkdir -p $GOPATH/src/github.com/letsencrypt/
git clone git://github.com/letsencrypt/boulder.git --branch release-2016-07-14 $GOPATH/src/github.com/letsencrypt/boulder
cd $GOPATH/src/github.com/letsencrypt/boulder
#sed -i -e 's/root@tcp/boulder:test@tcp/' policy/_db/dbconf.yml sa/_db/dbconf.yml
sed -i -e 's/-u root/-u boulder -ptest/' test/create_db.sh || true
go get -t ./...
go install -v ./...
./test/setup.sh || true
nohup python2.7 start.py &
sleep 2
