#!/bin/bash
cd "$(dirname "$0")"

docker-compose -p compose -f docker-compose.yml run scanner-extensions bash -c '/opt/scanner-extensions/docker/launch_compose_tests.sh'

let r=$?

docker stop compose_oob-dns_1
docker stop compose_scanner-test-app_1

exit $r
