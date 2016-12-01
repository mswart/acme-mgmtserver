#!/bin/bash
set -ex
eval "$(gimme 1.6)"
export GOPATH=~/build/go
export PATH=$PATH:$GOPATH/bin:$GOPATH/src/github.com/letsencrypt/boulder/bin:~/bin
mkdir -p $GOPATH/src/github.com/letsencrypt/
git clone git://github.com/letsencrypt/boulder.git --branch release-2016-07-14 $GOPATH/src/github.com/letsencrypt/boulder
cd $GOPATH/src/github.com/letsencrypt/boulder
sed -i -e 's/-u root/-u boulder -ptest/' test/create_db.sh

go get -v \
  bitbucket.org/liamstask/goose/cmd/goose \
  github.com/golang/lint/golint \
  github.com/golang/mock/mockgen \
  github.com/golang/protobuf/proto \
  github.com/golang/protobuf/protoc-gen-go \
  github.com/jsha/listenbuddy \
  github.com/kisielk/errcheck \
  github.com/mattn/goveralls \
  github.com/modocache/gover \
  github.com/tools/godep \
  golang.org/x/tools/cover

make GO_BUILD_FLAGS=''

go run cmd/rabbitmq-setup/main.go -server amqp://boulder-rabbitmq

./test/create_db.sh

nohup python2.7 start.py &
sleep 2
cat nohup.out
