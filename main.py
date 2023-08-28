#!/usr/bin/env python3

import re
import sys
import json
import zlib
import logging
import argparse
import time
import socket

import graypy

from parser import AuditLogParser


def get_handler(graylog_host, graylog_port):
    ignore_dn = re.compile(
        '.*,ou=UserPreferences,.*,o=NetscapeRoot$|cn=uniqueid generator,cn=config$'
    )
    ignore_attributes = {
        # mandatory attributes
        'dn',
        'time',
        'result',
        'changetype',
        'replace',

        # password/account policy attributes
        'lastlogintime',
        'passwordretrycount',
        'retrycountresettime',
        'accountunlocktime',

        # modifier attributes
        'modifiersname',
        'modifytimestamp',
    }

    gelf_handler = graypy.GELFUDPHandler(graylog_host, graylog_port)

    def handler(change_block):
        logging.debug("Handling change block: %r", change_block)
        if ignore_dn.match(change_block['dn'][0]):
            logging.debug("Ignoring change block due to ignored DN")
            return

        if change_block.get('changetype') != ['delete'] and not set(map(str.lower, change_block.keys())) - ignore_attributes:
            logging.debug("Ignoring change block because it only contains ignored attributes")
            return

        msg = {
            'version': '1.1',
            'host': socket.getfqdn(),
            'short_message': ' '.join((
                change_block['changetype'][0],
                change_block['dn'][0]
            )),
            'timestamp': time.mktime(time.strptime(
                change_block['time'][0],
                '%Y%m%d%H%M%S'
            )),
        }
        for k, v in change_block.items():
            if k == 'time':
                continue
            msg['_%s' % k] = v[0] if len(v) == 1 else repr(v)

        j = json.dumps(msg)
        logging.debug("Sending GELF message: %s", j)
        gelf_handler.send(zlib.compress(j.encode()))

    return handler


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--graylog-host', default='localhost')
    parser.add_argument('--graylog-port', type=int, default=12201)
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)

    parser = AuditLogParser(get_handler(args.graylog_host, args.graylog_port))
    if parser.parse_file(sys.stdin):
        # stdin closed, handle aborted block and exit
        parser.call_cb()
        sys.exit(1)

    sys.exit(0)
