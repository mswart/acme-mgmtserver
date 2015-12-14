#!/bin/bash
set -x
# add ppa for mariadb and rabbitmq (needs newer versions)
apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xcbcb082a1bb943db
echo 'deb http://mirror2.hs-esslingen.de/mariadb/repo/10.0/ubuntu trusty main' > /etc/apt/sources.list.d/mariadb.list
wget https://www.rabbitmq.com/rabbitmq-signing-key-public.asc -O - | apt-key add -
echo 'deb http://www.rabbitmq.com/debian/ testing main' > /etc/apt/sources.list.d/rabbitmq.list
# update package list
apt-get update -qq
# install packages
apt-get install -qq libltdl3-dev mariadb-server rabbitmq-server python2.7
# configure mariadb
# todo
mysql -u root <<EOF
CREATE USER boulder IDENTIFIED by "test";
GRANT ALL PRIVILEGES ON *.* TO 'boulder'@'%' with grant option;
FLUSH PRIVILEGES;
EOF
