#!/usr/bin/env bash
set -e
docker-compose up --build -d

# Ensure services have been started
sleep 3

TOKEN=`curl -f -X POST -H "Content-type: application/x-www-form-urlencoded" "localhost:8080/default/token" -d "grant_type=authorization_code&client_id=id&client_secret=secret&code=any_code&redirect_uri=anywhere" -s|jq -er '.access_token'`
curl -f -H "Authorization: Bearer ${TOKEN}" http://localhost:3000

echo OK

# Will not stop services if test above has failed
docker-compose down
