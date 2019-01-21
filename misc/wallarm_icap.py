#!/usr/bin/python

# Usage:
#
# 1. Register request handler in tarantool config
#
#    Add to /etc/wallarm/tarantool.lua:
#
#      wallarm.icap = require('wallarm_icap')
#
# 2. Configure regular start of export detected files
#
#    /usr/share/wallarm-extra-scripts/wallarm_icap.py
#

import sys
import os
import tarantool
import tempfile
import icapclient
import msgpack
import optparse
import logging

ICAP_PORT = 1344
TARANTOOL_PORT = 3313
URLENC_TYPE = 7
MULTIPART_TYPE = 1
POST_BODY_IDX = 23
POST_FAKE_KEY = '0'
ENTRY_VALUE_IDX = 1
POST_TYPES_IDX = 7
ICAP_SEND_THRESHOLD = 100

def icap_init(tnt_host, tnt_port, icap_host, icap_port):
    icap_conn = icapclient.ICAPConnection(icap_host, icap_port)
    tnt_conn = tarantool.connect(tnt_host, tnt_port)
    return (tnt_conn, icap_conn)

def icap_send(data, conn):
    tf = tempfile.NamedTemporaryFile()
    tf.write(data)
    tf.flush()
    conn.request('REQMOD', tf.name)
    tf.close()
    resp = conn.getresponse()
    logging.info('response from icap status {0} reason {1}'.format(resp.icap_status, resp.icap_reason))

def entry_value(entry):
    return entry[ENTRY_VALUE_IDX]

def type_process(entry_map, conn):
    for entry in entry_map.values():
        data = entry_value(entry)[0]
        logging.debug('length of decoded data {0}'.format(len(data)))
        if len(data) > ICAP_SEND_THRESHOLD:
            logging.debug('send to icap server')
            icap_send(data, conn)
    
def post_body_process(data, conn):
    req = msgpack.unpackb(data)
    post_entry = req[POST_BODY_IDX][POST_FAKE_KEY]
    post_types = entry_value(post_entry)[POST_TYPES_IDX]
    for key,val in post_types.items():
        if key in {MULTIPART_TYPE, URLENC_TYPE}:
            logging.debug('type of body {0}'.format(key))
            type_process(val, conn)
    
def icap_loop(tnt_conn, icap_conn):
    while True:
        resp = tnt_conn.call("wallarm.icap:get", [])
        for data in resp.data[0]:
            if len(data):
                logging.info('request from tarantool channel size {0}'.format(len(data)))
                post_body_process(data, icap_conn)
    
def main():
    parser = optparse.OptionParser(version='0.1', description='Send files from instance of Wallarm tarantool to ICAP server')
    parser.add_option('-l', '--logfile', type='string', action='store', dest='logfile', default='/var/log/wallarm/icap.log', help='path to logfile')
    parser.add_option('-L', '--loglevel', type='int', action='store', dest='loglevel', default=0, help='log level')
    parser.add_option('-t', '--tarantool', type='string', action='store', dest='tarantool', default='localhost', help='tarantool`s host')
    parser.add_option('-i', '--icap', type='string', action='store', dest='icap', default='localhost', help='icap`s host')
    parser.add_option('-p', '--icap-port', type='int', action='store', dest='icap_port', default=ICAP_PORT, help='icap`s port')
    parser.add_option('-P', '--tarantool-port', type='int', action='store', dest='tarantool_port', default=TARANTOOL_PORT, help='tarantool`s port')
    options, arguments = parser.parse_args()
    log_level = { 0 : logging.INFO, 10 : logging.DEBUG }.get(options.loglevel, logging.INFO)
    logging.basicConfig(filename=options.logfile,level=log_level, format='%(asctime)s %(message)s')
    icap_loop(*icap_init(options.tarantool, options.tarantool_port, options.icap, options.icap_port))

main()



