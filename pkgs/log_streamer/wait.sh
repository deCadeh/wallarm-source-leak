#!/bin/bash

cd "$(dirname "$0")"

let i=0
while (( i < 60 ))
do
  curl -s redis:6379 > /dev/null &&
  curl -s elasticsearch:9200 > /dev/null &&
  exec rspec
  sleep 1
  echo 'waiting for ready docker images...'
  (( i++ ))
done

echo 'Docker compose failed' >&2

exit 1
