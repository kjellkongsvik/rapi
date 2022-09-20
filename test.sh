#!/usr/bin/env bash
set -e
docker compose build
docker compose up -d

curl --head -X GET --connect-timeout 5 --retry 10 --retry-all-errors --retry-delay 1 http://localhost:3000/health
TOKEN=`curl -f -X POST -H "Content-type: application/x-www-form-urlencoded" "localhost:8080/default/token" -d "grant_type=authorization_code&client_id=id&client_secret=secret&code=any_code&redirect_uri=anywhere" -s|jq -er '.access_token'`
curl -f -H "Authorization: Bearer ${TOKEN}" http://localhost:3000

echo OK

docker compose down
