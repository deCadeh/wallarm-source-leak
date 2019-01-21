#!/bin/bash

cd "$(dirname "$0")/../"

let i=0
while [ $i -lt 10 ]
do
  curl -s oob-dns:8080 > /dev/null &&
  curl -s scanner-test-app > /dev/null &&
  exec rspec -c ./compose_spec/ --format documentation
  sleep 10
  echo 'waiting for ready docker images...'
  i=$(($i+1))
done

echo 'Docker compose failed'

exit 1
