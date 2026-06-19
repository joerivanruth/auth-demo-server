#!/usr/bin/env python3

import argparse
import logging
import os
import re
import socket
import threading

from framing import Mapi, ResultSet
from handshake import Handshake


def parse_sockaddr(s):
    try:
        n = int(s, 10)
        return ('localhost', n)
    except ValueError:
        host, port = s.rsplit(':', 1)
        port = int(port)
        return (host, port)


argparser = argparse.ArgumentParser()
argparser.add_argument(
    'listen_addr',
    type=parse_sockaddr,
    nargs='?',
    default='50000',
    help='[Host:]port to listen on, default is 50000',
)
argparser.add_argument('-k', '--keytab')
argparser.add_argument('-P', '--principal')
argparser.add_argument('-v', '--verbose', action='store_true')


def main(args):
    addrspec = args.listen_addr
    listen_socks = []
    for a in socket.getaddrinfo(host=addrspec[0], port=addrspec[1], type=socket.SOCK_STREAM):
        if a[0] in [socket.AF_INET, socket.AF_INET6]:
            sock = socket.create_server(address=a[4], family=a[0])
            logging.info(f'Listening on {sock.getsockname()}')
            listen_socks.append(sock)
    threads = [
        threading.Thread(target=accept_connections, args=(sock, args)) for sock in listen_socks
    ]
    for th in threads:
        th.start()


def accept_connections(listen_sock: socket.socket, args):
    while True:
        sock, peer = listen_sock.accept()
        id = pick_connection_id()
        logging.info(f'{id}: Incoming connection from {peer}')
        th = threading.Thread(target=handle_connection, args=(sock, id, args))
        th.start()


def handle_connection(sock: socket.socket, id: str, args):
    try:
        conn = Mapi(sock, id)
        hs = Handshake(conn, args)
        if hs.execute():
            interact(conn, hs)
    finally:
        logging.info(f'{id}: Closing')
        try:
            sock.close()
        except IOError:
            pass


def interact(conn: Mapi, hs: Handshake):
    while True:
        msg = conn.receive()
        if not msg:
            return
        if msg.startswith('Xclientinfo '):
            conn.send('')
            continue
        if msg[:1].lower() == 's' and interact_sql(conn, hs, msg[1:].strip(' \t\n;')):
            # interact_sql has handled it
            continue

        try:
            truncated_msg = msg.split('\n', 1)[0]
            conn.send(f"!42000!Demo server can't handle message: {truncated_msg}\n")
        except OSError:
            pass
        return


def interact_sql(conn: Mapi, hs: Handshake, sql: str) -> bool:
    # jdbcclient and mclient use this to retrieve env settings
    m = re.match(
        r"^SELECT \"?name\"?, \"?value\"? FROM \"?sys\"?.\"?env\"?\(\)(?: AS env)? WHERE \"?name\"? IN \(([a-z0-9_' ,]*)\)( UNION SELECT 'current_user' AS \"?name\"?, current_user as \"?value\"?)?",
        sql,
        re.I,
    )
    if m:
        requested = set(n.strip().strip("'") for n in m.group(1).split(','))
        rs = ResultSet('.env', name='varchar', value='varchar')
        if 'gdk_dbname' in requested:
            rs.add(name='gdk_dbname', value=hs.dbname)
        if 'revision' in requested:
            rs.add(name='revision', value='Unknown')
        if 'monet_version' in requested:
            rs.add(name='monet_version', value='56.0.0')
        if 'monet_release' in requested:
            rs.add(name='monet_release', value='Unknown')
        if 'max_clients' in requested:
            rs.add(name='max_clients', value='64')
        if 'monet_release' in requested:
            rs.add(name='raw_strings', value='false')
        if m.group(2):
            rs.add(name='current_user', value=hs.user)
        conn.send(rs.render())
        return True

    # jdbcclient needs this
    if sql.lower() == 'select current_schema':
        rs = ResultSet('.%2', **{'%2': 'varchar'})
        rs.add(**{'%2': 'sys'})
        conn.send(rs.render())
        return True

    # democlient uses this, also nice for interactive tests
    m = re.match(r'^SELECT\s+(\d+)\s*$', sql, re.I)
    if m:
        rs = ResultSet('.%2', **{'%2': 'int'})
        rs.add(**{'%2': int(m.group(1))})
        conn.send(rs.render())
        return True

    return False


def pick_connection_id() -> str:
    global connection_id_lock, connection_id_counter
    with connection_id_lock:
        id = connection_id_counter
        connection_id_counter += 1
        return f'#{id}'


connection_id_lock = threading.Lock()
connection_id_counter = 10


if __name__ == '__main__':
    args = argparser.parse_args()
    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=level)
    logging.debug(args)
    old_excepthook = threading.excepthook

    def my_excepthook(eargs, /):
        global old_excepthook
        old_excepthook(eargs)
        os._exit(1)

    threading.excepthook = my_excepthook
    main(args)
