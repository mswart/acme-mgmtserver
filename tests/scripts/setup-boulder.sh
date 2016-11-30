#!/bin/bash
set -ex
eval "$(gimme 1.6)"
export GOPATH=~/build/go
export PATH=$PATH:$GOPATH/bin:$GOPATH/src/github.com/letsencrypt/boulder/bin:~/bin
mkdir -p $GOPATH/src/github.com/letsencrypt/
git clone git://github.com/letsencrypt/boulder.git --branch hotfixes/2016-06-30 $GOPATH/src/github.com/letsencrypt/boulder
cd $GOPATH/src/github.com/letsencrypt/boulder
#sed -i -e 's/root@tcp/boulder:test@tcp/' policy/_db/dbconf.yml sa/_db/dbconf.yml
sed -i -e 's/-u root/-u boulder -ptest/' test/create_db.sh
make
# we need to install goose now, otherwise the test/create_db.sh call in test/setup.sh will be called before goose is installed
go get -v bitbucket.org/liamstask/goose/cmd/goose
./test/setup.sh
nohup python2.7 start.py &
sleep 2
cat nohup.out
