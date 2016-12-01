#!/bin/bash
set -ex
# add ppa for mariadb and rabbitmq (needs newer versions)
apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xcbcb082a1bb943db 0xe49303a769479fee
echo 'deb http://sfo1.mirrors.digitalocean.com//mariadb/repo/10.1/ubuntu trusty main' > /etc/apt/sources.list.d/mariadb.list
echo 'deb http://ppa.launchpad.net/5-james-t/protobuf-ppa/ubuntu trusty main' > /etc/apt/sources.list.d/protobuf.list
# update package list
apt-get update
# install packages
apt-get install -yV libltdl-dev mariadb-server mariadb-server-10.1 python2.7 libprotobuf-dev protobuf-compiler
# configure mariadb
# todo
mysql -u root <<EOF
CREATE USER boulder IDENTIFIED by "test";
GRANT ALL PRIVILEGES ON *.* TO 'boulder'@'%' with grant option;
FLUSH PRIVILEGES;
EOF
# define boulder needed hostnames
sed --in-place -e '/^127.0.0.1/ s/$/ boulder boulder-mysql boulder-rabbitmq/' /etc/hosts
