#!/bin/bash

echo "Stop PostgreSQL - container docker"
container_id=$(docker ps -a | grep "PostgreSQL" | awk '{print $1}')

if [ -n "$container_id" ]; then
    docker stop "$container_id"
    docker rm "$container_id"
    echo "Container PostgreSQL stopped successfully: $container_id"
else
    echo "Container docker no found."
fi