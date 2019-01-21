#!/bin/bash

set -e

cd /usr/share/elasticsearch

bin/elasticsearch &

ES_PID="$$"

/tmp/wait-for-it.sh 127.0.0.1:9200 -t 100

curl -XPUT 'http://127.0.0.1:9200/_template/log_record' -d '{"template":"*","mappings":{"log_record":{"properties":{"baseline_check_id":{"type":"long"},"time":{"type":"long"},"id":{"type":"keyword","index":"not_analyzed"}}}}}'

kill ${ES_PID}
sleep 5
kill -9 ${ES_PID} || :
