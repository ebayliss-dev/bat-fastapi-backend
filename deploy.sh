#!/bin/bash
set -e

# Stop and remove existing Redis container if it exists
docker stop redis-server 2>/dev/null || true
docker rm redis-server 2>/dev/null || true

# Pull the latest Redis image
docker pull redis:latest

# Bring up pawtul_api and redis services from docker-compose
sudo docker compose -f production.yml up -d --build pawtul_api redis

