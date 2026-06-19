#!/usr/bin/env python3

import argparse
import logging
import os
import socket
import stat
from typing import Optional, Tuple

from framing import Mapi
from pymonetdb.target import Target

import mechanisms


class ErrorMessage(Exception):
    pass


argparser = argparse.ArgumentParser()
argparser.add_argument(
    'dburl',
    help='Database to connect to, as an URL',
)
argparser.add_argument(
    '-m',
    '--methods',
    help='Comma separated list of allowed mechanisms',
    type=lambda s: [m.strip().upper() for m in s.split(',')],
)
argparser.add_argument('-v', '--verbose', action='store_true')


def main(args):
    target = Target()
    target.parse(args.dburl)
    mapi, target = connect(target, tuple(), args)
    logging.debug(f'Connected to {target.summary_url()}')

    mapi.send('sSELECT 42\n;')
    resp = mapi.receive()
    check_server_error(resp)
    mapi.close()


def connect(target: Target, enclosing_round, args) -> Tuple[Mapi, Target]:
    """Try to connect to the target.

    Multiple rounds may be needed because of redirects. Because of socket scanning,
    the rounds are nested.

    Returns the connection and the effective target, that is, the target after all
    redirects have been applied.
    """

    # do not accidentally update the caller's Target
    target = target.clone()

    # This loop exits on succesful connect.
    # It starts a new iteration on each redirect
    for inner_round in range(1, 11):
        round = enclosing_round + (inner_round,)
        str_round = '.'.join(str(n) for n in round)
        if len(round) > 3:
            raise ErrorMessage(f'Round {str_round}: Recursion too deep')

        logging.debug(f'==== Round {str_round}: connecting to {target.summary_url()}')

        # Follow the steps in https://github.com/MonetDBSolutions/monetdb-url-spec/blob/main/monetdb-url.md#connecting

        err: Optional[OSError | ErrorMessage] = None
        sock = None

        # Step 1: validation
        try:
            target.validate()
        except ValueError as e:
            raise ErrorMessage(f'Invalid target {target.summary_url()}: {e}')

        # Step 2: Scan Unix domain sockets
        if target.connect_scan:
            logging.debug(f'Scanning {target.connect_sockdir}')
            usocks = []
            try:
                usocks = scan_sockdir(target.connect_sockdir)
                logging.debug(f'Found {len(usocks)} candidates: {usocks}')
            except OSError as e:
                logging.debug(f'{e}')
                err = e
            if usocks:
                for s in usocks:
                    logging.debug(f'Round {str_round}: trying socket {s}')
                    subtarget = target.clone()
                    subtarget.host = ''
                    subtarget.sock = s
                    try:
                        return connect(subtarget, round, args)
                    except (ErrorMessage, OSError) as e:
                        logging.debug(f'Socket {s} failed, continuing: {e}')
                        err = e
                        continue
                else:
                    logging.debug('None of the Unix sockets succeeded')
            logging.debug('Falling back to TCP')
            target.sock = ''
            target.host = 'localhost'
            return connect(target, round, args)

        # Step 3: Unix socket
        if target.connect_unix and hasattr(socket, 'AF_UNIX'):
            logging.debug(f'Trying Unix domain socket {target.connect_unix}')
            try:
                sock = socket.socket(socket.AF_UNIX)
                sock.connect(target.connect_unix)
                logging.debug('Connection established')
                logging.debug("Sending mode byte '0'")
                sock.send(b'0')
            except OSError as e:
                logging.debug(f'{e}')
                err = e
                if sock:
                    sock.close()
                    sock = None

        # Step 4: TCP socket
        if not sock and target.connect_tcp:
            logging.debug(f'Trying TCP address {target.connect_tcp}')
            port = target.connect_port
            addrs = None
            try:
                addrs = socket.getaddrinfo(
                    host=target.connect_tcp, port=port, type=socket.SOCK_STREAM
                )
            except OSError as e:
                logging.debug(f'Cannot resolve {target.connect_tcp}: {e}')
                err = e
                if sock:
                    sock.close()
                    sock = None
            if addrs:
                for a in addrs:
                    logging.debug(f'Trying addr {a[4]}')
                    try:
                        sock = socket.socket(family=a[0])
                        sock.connect(a[4])
                        logging.debug('Connection established')
                        break
                    except OSError as e:
                        logging.debug(f'{e}')
                        err = e
                        if sock:
                            sock.close()
                            sock = None

        # Step 5: report errors
        if not sock:
            assert err
            raise err

        # Step 6: TLS
        if target.tls:
            raise ErrorMessage('TLS is not supported yet (we really should!)')

        # Step 7: login
        mapi = Mapi(sock, 'connection')
        redirect = login(target, mapi, args)
        if redirect:
            logging.debug(f'Applying redirect {redirect} and restarting')
            target.parse(redirect)
            continue

        # Step 8: victory!
        return (mapi, target)

    else:
        raise ErrorMessage(f'Target {target.summary_url()}: too many redirects')


def scan_sockdir(dir) -> list[str]:
    if not os.path.exists(dir):
        logging.debug(f'{dir} does not exist')
        return []
    my_socks = []
    other_socks = []
    my_uid = os.geteuid()
    for entry in os.listdir(dir):
        if not entry.startswith('.s.monetdb.'):
            continue
        try:
            path = os.path.join(dir, entry)
            st = os.stat(path)
            if not stat.S_ISSOCK(st.st_mode):
                continue
            if st.st_uid == my_uid:
                my_socks.append(path)
            else:
                other_socks.append(path)
        except OSError:
            pass
    return my_socks + other_socks


def login(target: Target, mapi: Mapi, args):
    for i in range(10):
        response = attempt_login(target, mapi, args)
        if response.startswith('!'):
            raise ErrorMessage(response[1:])
        prefix = '^mapi:merovingian://proxy?'
        if response.startswith(prefix):
            remainder = response[len(prefix) :]
            logging.debug(f'Restarting on same connection with {remainder}')
            for kv in remainder.split('&'):
                k, v = kv.split('=', 1)
                target.set(k, v)
            continue
        else:
            return response[1:]

    raise ErrorMessage('Too many internal redirects')


def attempt_login(target: Target, mapi: Mapi, args):
    server_challenge = mapi.receive()
    check_server_error(server_challenge)
    if not server_challenge:
        raise ErrorMessage('server immediately closed the connection')
    assert server_challenge.endswith(':')
    parts = server_challenge.split(':')[:-1]
    if len(parts) < 3:
        raise ErrorMessage('incomplete challenge')
    [nonce, servertype, proto, available_mechs_str, endian, obfusc_algo, *rest] = parts
    if proto != '9':
        raise ErrorMessage('Only protocol version 9 is supported, not {proto}')

    if servertype == 'merovingian':
        target = target.clone()
        target.user = 'merovingian'
        target.password = 'merovingian'

    assert available_mechs_str is not None
    available_mechs = set(available_mechs_str.split(','))
    if args.methods:
        available_mechs &= set(args.methods)
    for mech in mechanisms.MECHANISMS:
        if mech.wire_name in available_mechs:
            break
    else:
        raise ErrorMessage(f'No supported authentication mechanism among {available_mechs_str}')

    ctx = mech.start_client(target)
    response = str(ctx.respond(bytes(nonce, 'utf-8')), 'utf-8')
    reply = f'BIG:{target.user}:{{{mech.wire_name}}}{response}:sql:{target.database}:'
    mapi.send(reply)

    server_response = mapi.receive()
    if server_response is None:
        raise ErrorMessage('server closed the connection during login')
    check_server_error(server_response)
    first_line = server_response.strip().split('\n', 1)[0]
    return first_line


def check_server_error(msg):
    if msg is not None and msg.startswith('!'):
        errmsg = msg[1:].split('\n', 1)[0]
        raise ErrorMessage(errmsg)


if __name__ == '__main__':
    args = argparser.parse_args()
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=level)
    logging.debug(args)
    try:
        exit(main(args) or 0)
    except ErrorMessage as e:
        logging.error(str(e))
        exit(1)
