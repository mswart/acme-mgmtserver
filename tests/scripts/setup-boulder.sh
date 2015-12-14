#!/bin/bash
sed -x
env
eval "$(gimme 1.5)"
export GOPATH=~/build/go
export PATH=$PATH:$GOPATH/bin
mkdir ~/build/letsencrypt
git clone git://github.com/letsencrypt/boulder.git --branch release-2015-12-07
mkdir -p $GOPATH/src/github.com/letsencrypt/
ln -s ~/build/letsencrypt/boulder $GOPATH/src/github.com/letsencrypt/boulder
cd ~/build/letsencrypt/boulder
sed -i -e 's/root@tcp/boulder:test@tcp/' policy/_db/dbconf.yml sa/_db/dbconf.yml
sed -i -e 's/-u root/-u boulder -ptest/' test/create_db.sh
./test/setup.sh
nohup python2.7 start.py &
