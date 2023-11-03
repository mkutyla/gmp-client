#!/bin/sh

sudo apt upgrade
sudo apt install docker.io
sudo apt install python3 python3-pip

python3 -m pip install --user docker-compose
python3 -m pip install python-gvm
python3 -m pip install yagmail
python3 -m pip install schedule

GBONE=greenbone-community-container

mkdir -p /tmp/gvm/gvmd
chmod -R 777 /tmp/gvm
mkdir -p /tmp/osp/ospd
chmod -R 777 /tmp/osp

mkdir -p /tmp/bso_reports
chmod -R 777 /tmp/bso_reports

docker-compose -f $GBONE/docker-compose.yml -p greenbone-community-edition pull

docker-compose -f $GBONE/docker-compose.yml -p greenbone-community-edition up -d

