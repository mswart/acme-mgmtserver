#!/bin/bash
set -ex
# add ppa for mariadb and rabbitmq (needs newer versions)
apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xcbcb082a1bb943db
echo 'deb http://sfo1.mirrors.digitalocean.com//mariadb/repo/10.1/ubuntu trusty main' > /etc/apt/sources.list.d/mariadb.list
# update package list
apt-get update
# install packages
apt-get install -yV libltdl-dev mariadb-server mariadb-server-10.1 python2.7
# configure mariadb
# todo
mysql -u root <<EOF
CREATE USER boulder IDENTIFIED by "test";
GRANT ALL PRIVILEGES ON *.* TO 'boulder'@'%' with grant option;
FLUSH PRIVILEGES;
EOF
