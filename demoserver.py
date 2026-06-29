#!/usr/bin/env python3

import argparse
import logging
import os
import re
import socket
import threading

from credentials import Cred, CredStore
import credentials
from framing import Mapi, ResultSet
from handshake import Handshake
from mechanisms import Reject, Style


def parse_sockaddr(s):
    try:
        n = int(s, 10)
        return ('localhost', n)
    except ValueError:
        host, port = s.rsplit(':', 1)
        port = int(port)
        return (host, port)


def parse_credentials(arg) -> Cred:
    m = re.match(r'^([a-zA-Z_0-9]+)=(\w+):(\S+)$', arg)
    if not m:
        raise ValueError('Expect USER=METHOD:PASSWORD_DATA, not "{arg}"')
    return Cred(m.group(1), m.group(2), m.group(3))


argparser = argparse.ArgumentParser()
argparser.add_argument(
    'listen_addr',
    type=parse_sockaddr,
    nargs='?',
    default='50000',
    help='[Host:]port to listen on, default is 50000',
)
argparser.add_argument(
    '-m',
    '--methods',
    help='Comma separated list of allowed mechanisms',
    type=lambda s: [m.strip().upper() for m in s.split(',')],
)
argparser.add_argument('-k', '--keytab')
argparser.add_argument(
    '-c',
    '--credential',
    action='append',
    type=parse_credentials,
    dest='credentials',
    help='Set credentials of the form USER=METHOD:PASSWORD',
)
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
    if args.credentials:
        creds = CredStore()
        for cred in args.credentials:
            creds.add(cred.user, cred.kind, cred.password)
    else:
        creds = CredStore.default()

    conn = Mapi(sock, id)
    try:
        hs = Handshake(conn, creds, args)
        final_message = hs.execute()
        authorize_connection(id, hs)
        assert hs.server_side
        authcid = hs.server_side.authcid
        logging.debug(f"{id}: Authorized '{authcid}' to log in as '{hs.user}'")
        conn.send(final_message)
    except Reject as e:
        logging.error(f'{id}: {e}')
        try:
            conn.send(f'!{e.client_message}')
        except IOError:
            pass
    else:
        interact(conn, hs)
    finally:
        logging.info(f'{id}: Closing')
        try:
            sock.close()
        except IOError:
            pass


def authorize_connection(id: str, hs: Handshake):
    assert hs.server_side
    assert hs.user
    assert hs.mech
    authcid = hs.server_side.authcid
    authzid = hs.server_side.authzid
    assert authcid
    assert isinstance(authcid, str)

    # authcid is mechanism-specific, usually a plain identifier
    # such as 'monetdb'. It can also be something else, such as
    # a Kerberos principal.

    # authzid is monetdb-specific. It's a SQL user name.
    # It's usually left empty. We only support empty and
    # identical to the handshake user.

    if authzid and authzid != hs.user:
        raise Reject(f"SASL authzid '{authzid}' must equal handshake user '{hs.user}")

    if hs.mech.style == Style.PASSWORD:
        # The mechanism has already verified that the user supplied the right password,
        # we're done
        return

    # With the other mechanisms, we check if the authcid is known to be allowed
    # to connect as this user.
    # We use the
    permitted = hs.credstore.get_all(hs.user, credentials.PRINCIPAL)
    if authcid in permitted:
        return

    errmsg = f"{id}: External identity '{authcid}' not allowed to authenticate as '{hs.user}'"
    for cred in hs.credstore[hs.user].list():
        errmsg += f"\n- cred type '{cred.kind}': '{cred.password}'"
    raise Reject(errmsg)


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
            assert hs.user
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
    logformat = 'SERVER:  %(message)s'
    logging.basicConfig(level=level, format=logformat)
    logging.debug(args)
    old_excepthook = threading.excepthook

    def my_excepthook(eargs, /):
        global old_excepthook
        old_excepthook(eargs)
        os._exit(1)

    threading.excepthook = my_excepthook
    main(args)
