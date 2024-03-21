#!/bin/sh
echo "Start container jpengineer/centos7-postgresql15"
echo "PostgreSQL 15 - Centos 7 - Docker"
echo "Name: PostgreSQL"
docker run -d -it -v /Users/juan/Documents/Minor_Projects/Dockers/Postgresql/sql:/docker-entrypoint-initdb.d -v /Users/juan/Documents/Minor_Projects/Dockers/Postgresql/sh:/scripts -p 5432:5432 --name PostgreSQL jpengineer/centos7-postgresql15
sleep 5
docker ps -a